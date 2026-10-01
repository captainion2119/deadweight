"""Populate a moto-mocked AWS account with a representative spread of resources."""
import io
import json
import os
import zipfile

os.environ.update(AWS_ACCESS_KEY_ID="testing", AWS_SECRET_ACCESS_KEY="testing", AWS_SECURITY_TOKEN="testing",
                  AWS_SESSION_TOKEN="testing", AWS_DEFAULT_REGION="us-east-1")
import boto3  # noqa: E402

REGIONS = ["us-east-1", "eu-west-1", "ap-southeast-2"]
FAILED: list[str] = []


def step(name):
    def deco(fn):
        def run(*a, **k):
            try:
                return fn(*a, **k)
            except Exception as e:  # moto gaps are recorded, not fatal
                FAILED.append(f"{name}: {type(e).__name__}: {str(e)[:120]}")
        run.__name__ = fn.__name__
        return run
    return deco


def _zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("lambda_function.py", "def handler(e, c):\n    return 1\n")
    return buf.getvalue()


def populate():
    s = {}
    for region in REGIONS[:2]:
        ec2 = boto3.client("ec2", region_name=region)
        vpc = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
        subnets = [x["SubnetId"] for x in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc]}])["Subnets"]]
        s[region] = {"vpc": vpc, "subnets": subnets}

    @step("ec2")
    def ec2_stuff():
        ec2 = boto3.client("ec2", region_name="us-east-1")
        sub = s["us-east-1"]["subnets"][0]
        ami = ec2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
        r = ec2.run_instances(ImageId=ami, MinCount=2, MaxCount=2, InstanceType="t3.micro", SubnetId=sub,
                              TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": "web"}, {"Key": "env", "Value": "prod"}]}])
        ids = [i["InstanceId"] for i in r["Instances"]]
        stopped = ec2.run_instances(ImageId=ami, MinCount=1, MaxCount=1, InstanceType="m4.large", SubnetId=sub)["Instances"][0]["InstanceId"]
        ec2.stop_instances(InstanceIds=[stopped])
        s["instances"], s["stopped"] = ids, stopped
        v1 = ec2.create_volume(AvailabilityZone="us-east-1a", Size=100, VolumeType="gp2")["VolumeId"]
        ec2.create_volume(AvailabilityZone="us-east-1a", Size=500, VolumeType="gp3", Iops=6000, Throughput=250)
        ec2.create_volume(AvailabilityZone="us-east-1a", Size=200, VolumeType="io2", Iops=40000)
        ec2.create_snapshot(VolumeId=v1, Description="nightly")
        ec2.create_image(InstanceId=ids[0], Name="golden-ami")
        a1 = ec2.allocate_address(Domain="vpc")
        ec2.associate_address(AllocationId=a1["AllocationId"], InstanceId=ids[0])
        ec2.allocate_address(Domain="vpc")
        nat_eip = ec2.allocate_address(Domain="vpc")["AllocationId"]
        ec2.create_nat_gateway(SubnetId=sub, AllocationId=nat_eip)
        ec2.create_vpc_endpoint(VpcId=s["us-east-1"]["vpc"], ServiceName="com.amazonaws.us-east-1.ssm", VpcEndpointType="Interface",
                                SubnetIds=s["us-east-1"]["subnets"][:2])
        ec2.create_vpc_endpoint(VpcId=s["us-east-1"]["vpc"], ServiceName="com.amazonaws.us-east-1.s3", VpcEndpointType="Gateway")
        e2 = boto3.client("ec2", region_name="eu-west-1")
        ami2 = e2.describe_images(Owners=["amazon"])["Images"][0]["ImageId"]
        e2.run_instances(ImageId=ami2, MinCount=1, MaxCount=1, InstanceType="t3.small", SubnetId=s["eu-west-1"]["subnets"][0])
        tgw = ec2.create_transit_gateway(Description="core")["TransitGateway"]["TransitGatewayId"]
        ec2.create_transit_gateway_vpc_attachment(TransitGatewayId=tgw, VpcId=s["us-east-1"]["vpc"], SubnetIds=[sub])

    @step("elb")
    def elb_stuff():
        elbv2 = boto3.client("elbv2", region_name="us-east-1")
        lb = elbv2.create_load_balancer(Name="app-lb", Subnets=s["us-east-1"]["subnets"][:2], Type="application")["LoadBalancers"][0]
        tg = elbv2.create_target_group(Name="app-tg", Protocol="HTTP", Port=80, VpcId=s["us-east-1"]["vpc"])["TargetGroups"][0]
        elbv2.create_listener(LoadBalancerArn=lb["LoadBalancerArn"], Protocol="HTTP", Port=80,
                              DefaultActions=[{"Type": "forward", "TargetGroupArn": tg["TargetGroupArn"]}])
        boto3.client("elb", region_name="us-east-1").create_load_balancer(
            LoadBalancerName="legacy-clb", Listeners=[{"Protocol": "HTTP", "LoadBalancerPort": 80, "InstancePort": 80}],
            AvailabilityZones=["us-east-1a"])

    @step("rds")
    def rds_stuff():
        rds = boto3.client("rds", region_name="us-east-1")
        rds.create_db_instance(DBInstanceIdentifier="orders-staging", Engine="postgres", DBInstanceClass="db.t4g.small",
                               AllocatedStorage=20, StorageType="gp3", MultiAZ=True, MasterUsername="u", MasterUserPassword="password123")
        rds.create_db_cluster(DBClusterIdentifier="analytics", Engine="aurora-postgresql", MasterUsername="u",
                              MasterUserPassword="password123", ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 4})
        rds.create_db_snapshot(DBSnapshotIdentifier="orders-old", DBInstanceIdentifier="orders-staging")

    @step("iam+lambda")
    def lambda_stuff():
        iam = boto3.client("iam")
        role = iam.create_role(RoleName="lambda-role", AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}))["Role"]["Arn"]
        lam = boto3.client("lambda", region_name="us-east-1")
        lam.create_function(FunctionName="api-handler", Runtime="python3.12", Role=role, Handler="lambda_function.handler",
                            Code={"ZipFile": _zip()}, MemorySize=512)
        try:
            lam.create_function(FunctionName="image-fn", Role=role, Code={"ImageUri": "123456789012.dkr.ecr.us-east-1.amazonaws.com/x:latest"},
                                PackageType="Image", MemorySize=1024)
        except Exception as e:
            FAILED.append(f"lambda image fn: {e}")
        iam.create_user(UserName="ci-bot")
        iam.create_access_key(UserName="ci-bot")

    @step("ecs")
    def ecs_stuff():
        ecs = boto3.client("ecs", region_name="us-east-1")
        ecs.create_cluster(clusterName="prod")
        td = ecs.register_task_definition(family="api", requiresCompatibilities=["FARGATE"], networkMode="awsvpc", cpu="1024",
                                          memory="2048", runtimePlatform={"cpuArchitecture": "ARM64", "operatingSystemFamily": "LINUX"},
                                          containerDefinitions=[{"name": "api", "image": "nginx", "essential": True}])["taskDefinition"]
        ecs.create_service(cluster="prod", serviceName="api", taskDefinition=td["taskDefinitionArn"], desiredCount=2, launchType="FARGATE",
                           networkConfiguration={"awsvpcConfiguration": {"subnets": s["us-east-1"]["subnets"][:1], "securityGroups": []}})

    @step("eks")
    def eks_stuff():
        iam = boto3.client("iam")
        boto3.client("eks", region_name="us-east-1").create_cluster(
            name="k8s", roleArn="arn:aws:iam::123456789012:role/eks", resourcesVpcConfig={"subnetIds": s["us-east-1"]["subnets"][:2]})

    @step("s3")
    def s3_stuff():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="logs-bucket-use1")
        s3.create_bucket(Bucket="data-bucket-euw1", CreateBucketConfiguration={"LocationConstraint": "eu-west-1"})
        s3.put_bucket_lifecycle_configuration(Bucket="logs-bucket-use1", LifecycleConfiguration={"Rules": [
            {"ID": "expire", "Status": "Enabled", "Filter": {"Prefix": ""}, "Expiration": {"Days": 30}}]})

    @step("misc")
    def misc():
        boto3.client("dynamodb", region_name="us-east-1").create_table(
            TableName="sessions", KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
            ProvisionedThroughput={"ReadCapacityUnits": 50, "WriteCapacityUnits": 10})
        boto3.client("apigateway", region_name="us-east-1").create_rest_api(name="public-api")
        boto3.client("apigatewayv2", region_name="us-east-1").create_api(Name="http-api", ProtocolType="HTTP")
        r53 = boto3.client("route53")
        r53.create_hosted_zone(Name="example.com", CallerReference="1")
        r53.create_health_check(CallerReference="hc1", HealthCheckConfig={"Type": "HTTPS", "FullyQualifiedDomainName": "example.com",
                                                                            "RequestInterval": 10})
        boto3.client("ecr", region_name="us-east-1").create_repository(repositoryName="api")
        boto3.client("secretsmanager", region_name="us-east-1").create_secret(Name="db-password", SecretString="x")
        boto3.client("sqs", region_name="us-east-1").create_queue(QueueName="jobs")
        boto3.client("sns", region_name="us-east-1").create_topic(Name="alerts")
        kms = boto3.client("kms", region_name="us-east-1")
        kms.create_key(Description="app key")
        k2 = kms.create_key(Description="old key")["KeyMetadata"]["KeyId"]
        kms.disable_key(KeyId=k2)
        logs = boto3.client("logs", region_name="us-east-1")
        logs.create_log_group(logGroupName="/app/api")
        logs.create_log_group(logGroupName="/app/worker")
        logs.put_retention_policy(logGroupName="/app/worker", retentionInDays=14)
        boto3.client("cloudwatch", region_name="us-east-1").put_metric_alarm(
            AlarmName="cpu-high", MetricName="CPUUtilization", Namespace="AWS/EC2", Statistic="Average", Period=300,
            EvaluationPeriods=1, Threshold=80, ComparisonOperator="GreaterThanThreshold")
        boto3.client("efs", region_name="us-east-1").create_file_system(CreationToken="fs1")
        boto3.client("kinesis", region_name="us-east-1").create_stream(StreamName="events", ShardCount=4)
        boto3.client("backup", region_name="us-east-1").create_backup_vault(BackupVaultName="vault1")
        boto3.client("stepfunctions", region_name="us-east-1").create_state_machine(
            name="flow", definition=json.dumps({"StartAt": "A", "States": {"A": {"Type": "Pass", "End": True}}}),
            roleArn="arn:aws:iam::123456789012:role/sf")
        boto3.client("glue", region_name="us-east-1").create_job(Name="etl", Role="r", Command={"Name": "glueetl", "ScriptLocation": "s3://x/y"})

    @step("waf")
    def waf():
        boto3.client("wafv2", region_name="us-east-1").create_web_acl(
            Name="edge", Scope="REGIONAL", DefaultAction={"Allow": {}},
            VisibilityConfig={"SampledRequestsEnabled": False, "CloudWatchMetricsEnabled": False, "MetricName": "x"},
            Rules=[{"Name": "r1", "Priority": 1, "Action": {"Block": {}},
                    "Statement": {"ByteMatchStatement": {"SearchString": "bad", "FieldToMatch": {"UriPath": {}},
                                                         "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                                                         "PositionalConstraint": "CONTAINS"}},
                    "VisibilityConfig": {"SampledRequestsEnabled": False, "CloudWatchMetricsEnabled": False, "MetricName": "r1"}}])

    @step("transfer")
    def transfer():
        boto3.client("transfer", region_name="us-east-1").create_server(Protocols=["SFTP", "FTPS"], IdentityProviderType="SERVICE_MANAGED")

    @step("pca")
    def pca():
        boto3.client("acm-pca", region_name="us-east-1").create_certificate_authority(
            CertificateAuthorityConfiguration={"KeyAlgorithm": "RSA_2048", "SigningAlgorithm": "SHA256WITHRSA",
                                               "Subject": {"CommonName": "internal.example"}},
            CertificateAuthorityType="ROOT")

    @step("elasticache")
    def elasticache():
        boto3.client("elasticache", region_name="us-east-1").create_cache_cluster(
            CacheClusterId="cache1", Engine="redis", CacheNodeType="cache.t3.micro", NumCacheNodes=1)

    @step("opensearch")
    def opensearch():
        boto3.client("opensearch", region_name="us-east-1").create_domain(
            DomainName="search", ClusterConfig={"InstanceType": "r6g.large.search", "InstanceCount": 2},
            EBSOptions={"EBSEnabled": True, "VolumeSize": 100, "VolumeType": "gp3"})

    @step("redshift")
    def redshift():
        boto3.client("redshift", region_name="us-east-1").create_cluster(
            ClusterIdentifier="dw", NodeType="ra3.xlplus", MasterUsername="u", MasterUserPassword="Password123", ClusterType="multi-node",
            NumberOfNodes=2)

    @step("tags")
    def tags():
        # Tag a few resources so the Tagging API reports duplicates of direct-API resources.
        tagging_targets = []
        ec2 = boto3.client("ec2", region_name="us-east-1")
        vols = ec2.describe_volumes()["Volumes"]
        ec2.create_tags(Resources=[v["VolumeId"] for v in vols], Tags=[{"Key": "team", "Value": "data"}])
        return tagging_targets

    for fn in (ec2_stuff, elb_stuff, rds_stuff, lambda_stuff, ecs_stuff, eks_stuff, s3_stuff, misc, waf, transfer, pca,
               elasticache, opensearch, redshift, tags):
        fn()
    return s
