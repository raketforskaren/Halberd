from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, AzureTRMTechnique
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.azure.azure_access import AzureAccess
import subprocess
import json

@TechniqueRegistry.register
class AzureEstablishAccessAsUser(BaseTechnique):
    def __init__(self):
        mitre_techniques = [
            MitreTechnique(
                technique_id="T1078.004",
                technique_name="Valid Accounts",
                tactics=["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
                sub_technique_name="Cloud Accounts"
            )
        ]
        azure_trm_technique = [
            AzureTRMTechnique(
                technique_id="AZT201.1",
                technique_name="Valid Credentials",
                tactics=["Initial Access"],
                sub_technique_name="User Account"
            )
        ]
        super().__init__("Establish Access As User", "Authenticates to an Azure tenant using username and password credentials. This technique is intended for non-MFA Azure user accounts where direct Azure CLI credential-based login is permitted. For MFA-enabled accounts or tenants that require interactive authentication, use Establish Access via Browser Login instead. Successfully authenticated sessions return information about accessible subscriptions including subscription IDs, account details, and tenant associations.", mitre_techniques, azure_trm_technique)
        

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        try:
            # input validation
            username: str = kwargs['username']
            password: str = kwargs['password']

            if username in ["", None] or password in ["", None]:
                return ExecutionStatus.FAILURE, {
                    "error": {"Error" : "Invalid Technique Input"},
                    "message": {"Error" : "Invalid Technique Input"}
                }
            
            # get az full execution path
            az_command = AzureAccess().az_command
            raw_response = subprocess.run([az_command, "login", "-u", username, "-p", password], capture_output=True)

            if raw_response.returncode != 0:
                stderr_output = raw_response.stderr.decode("utf-8", errors="ignore").strip()
                stdout_output = raw_response.stdout.decode("utf-8", errors="ignore").strip()
                combined_output = f"{stderr_output}\n{stdout_output}".strip()
                lowered_output = combined_output.lower()

                if any(keyword in lowered_output for keyword in [
                    "interactive authentication is needed",
                    "multifactor authentication",
                    "mfa",
                    "conditional access",
                    "device code",
                    "browser"
                ]):
                    return ExecutionStatus.FAILURE, {
                        "error": combined_output or str(raw_response.returncode),
                        "message": "Azure CLI requires interactive authentication for this account. Use 'Establish Access via Browser Login' for MFA-enabled or Conditional Access-protected users."
                    }

            if raw_response.returncode == 0:
                output = raw_response.stdout
                struc_output = json.loads(output.decode('utf-8'))

                try:
                    output = {}
                    for subscription in struc_output:
                        output[subscription.get("id", "N/A")] = {
                            "subscription_name" : subscription.get("name", "N/A"),
                            "subscription_id" : subscription.get("id", "N/A"),
                            "home_tenant_id" : subscription.get("homeTenantId", "N/A"),
                            "state" : subscription.get("state", "N/A"),
                            "identity" : subscription.get("user", "N/A").get("name","N/A"),
                            "identity_type" : subscription.get("user", "N/A").get("type","N/A"),
                        }
                    return ExecutionStatus.SUCCESS, {
                        "message": f"Successfully established access to target Azure tenant",
                        "value": output
                    }
                except:
                    return ExecutionStatus.PARTIAL_SUCCESS, {
                        "message": "Successfully established access to target Azure tenant",
                        "value": struc_output
                    }
            else:
                return ExecutionStatus.FAILURE, {
                    "error": raw_response.stderr.decode("utf-8", errors="ignore").strip() or str(raw_response.returncode),
                    "message": "Failed to establish access to Azure tenant"
                }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to establish access to Azure tenant"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "username": {"type": "str", "required": True, "default": None, "name": "Username", "input_field_type" : "text"},
            "password": {"type": "str", "required": True, "default": None, "name": "Password", "input_field_type" : "password"}
        }
