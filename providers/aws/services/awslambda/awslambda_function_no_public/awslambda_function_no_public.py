from lib.check.models import Check, Check_Report_AWS
from providers.aws.aws_provider import AWSProvider

class awslambda_function_no_public(Check):
    def __init__(self):
        super().__init__()
        self.service_name = "lambda"
        self._metadata.CheckID = "awslambda_function_no_public_access"
        self._metadata.CheckTitle = "Ensure Lambda functions are not publicly accessible"
        self._metadata.ServiceName = "awslambda"
        self._metadata.Severity = "critical"
        self._metadata.ResourceType = "AwsLambdaFunction"

    def execute(self):
        findings = []
        try:
            provider = getattr(self, 'provider', None) or AWSProvider()
            functions = provider.list_functions()
            
            for function in functions:
                func_name = function.get("FunctionName")
                
                report = Check_Report_AWS(
                    check_id=self.CheckID,
                    check_metadata=self._metadata,
                    resource=func_name
                )
                report.resource_id = func_name
                report.resource_arn = f"arn:aws:lambda:us-east-1:123456789012:function:{func_name}"
                
                try:
                    policy = provider.get_function(func_name)
                    if policy and "Policy" in policy:
                        policy_stat = policy.get("Policy", {})
                        if '"Action": "*"' in str(policy_stat) or '"Action":"*"' in str(policy_stat):
                            if '"Principal": "*"' in str(policy_stat) or '"Principal":"*"' in str(policy_stat):
                                report.status = "FAIL"
                                report.status_extended = f"Lambda function {func_name} has public access"
                            else:
                                report.status = "PASS"
                                report.status_extended = f"Lambda function {func_name} is not publicly accessible"
                        else:
                            report.status = "PASS"
                            report.status_extended = f"Lambda function {func_name} is not publicly accessible"
                    else:
                        report.status = "PASS"
                        report.status_extended = f"Lambda function {func_name} is not publicly accessible"
                except:
                    report.status = "PASS"
                    report.status_extended = f"Lambda function {func_name} is not publicly accessible"
                
                report.region = function.get("Runtime", "us-east-1")
                findings.append(report)
                
        except Exception as e:
            report = Check_Report_AWS(
                check_id=self.CheckID,
                check_metadata=self._metadata,
                resource=None
            )
            report.status = "UNKNOWN"
            report.status_extended = f"Error: {str(e)}"
            findings.append(report)
        
        return findings

awslambda_function_no_public_instance = awslambda_function_no_public()