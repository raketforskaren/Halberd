from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, AzureTRMTechnique, TechniqueReference, TechniqueNote
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.azure.azure_access import AzureAccess
import subprocess
import json


@TechniqueRegistry.register
class AzureEstablishAccessViaBrowserLogin(BaseTechnique):
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

        technique_references = [
            TechniqueReference(
                "Authenticate Azure CLI interactively",
                "https://learn.microsoft.com/en-us/cli/azure/authenticate-azure-cli-interactively"
            ),
            TechniqueReference(
                "Authenticate to Azure using Azure CLI",
                "https://learn.microsoft.com/en-us/cli/azure/authenticate-azure-cli"
            )
        ]

        technique_notes = [
            TechniqueNote("Use this technique for MFA-enabled Azure user accounts when username/password login is blocked or unsupported."),
            TechniqueNote("This technique relies on the Azure CLI interactive browser login flow and works best when Halberd runs on a host that can launch a browser."),
            TechniqueNote("If the tenant blocks device code flow through Conditional Access, browser login may still be a viable user-authentication path."),
            TechniqueNote("Authentication must complete in the browser before Halberd can query the active Azure CLI session.")
        ]

        super().__init__(
            "Establish Access via Browser Login",
            "Authenticates to an Azure tenant using the Azure CLI's interactive browser login flow. This technique is intended for MFA-enabled user accounts where username/password authentication is unsupported and device code flow may be restricted by Conditional Access. After the user completes authentication in the browser, Halberd retrieves the active Azure CLI session and returns tenant and subscription details for follow-on Azure techniques.",
            mitre_techniques,
            azure_trm_technique,
            references=technique_references,
            notes=technique_notes
        )

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)

        try:
            tenant_id: str = kwargs.get("tenant_id", None)
            allow_no_subscriptions: bool = kwargs.get("allow_no_subscriptions", True)

            azure_access = AzureAccess()
            az_command = azure_access.az_command

            if not az_command:
                return ExecutionStatus.FAILURE, {
                    "error": "Azure CLI not found",
                    "message": "Azure CLI is not installed or not accessible"
                }

            login_command = [az_command, "login"]

            if tenant_id not in [None, ""]:
                login_command.extend(["--tenant", tenant_id])

            if allow_no_subscriptions:
                login_command.append("--allow-no-subscriptions")

            raw_response = subprocess.run(login_command, capture_output=True, text=True)

            if raw_response.returncode != 0:
                error_message = raw_response.stderr.strip() or raw_response.stdout.strip() or "Azure browser login did not complete successfully"
                return ExecutionStatus.FAILURE, {
                    "error": error_message,
                    "message": "Failed to establish access to Azure tenant via browser login"
                }

            try:
                struc_output = json.loads(raw_response.stdout)
            except json.JSONDecodeError:
                struc_output = None

            if isinstance(struc_output, list):
                try:
                    output = {}
                    for subscription in struc_output:
                        output[subscription.get("id", "N/A")] = {
                            "subscription_name": subscription.get("name", "N/A"),
                            "subscription_id": subscription.get("id", "N/A"),
                            "home_tenant_id": subscription.get("homeTenantId", "N/A"),
                            "state": subscription.get("state", "N/A"),
                            "identity": subscription.get("user", {}).get("name", "N/A"),
                            "identity_type": subscription.get("user", {}).get("type", "N/A"),
                        }
                    return ExecutionStatus.SUCCESS, {
                        "message": "Successfully established access to target Azure tenant via browser login",
                        "value": output
                    }
                except Exception:
                    return ExecutionStatus.PARTIAL_SUCCESS, {
                        "message": "Successfully established access to target Azure tenant via browser login",
                        "value": struc_output
                    }

            current_access = azure_access.get_current_subscription_info()
            if current_access:
                return ExecutionStatus.SUCCESS, {
                    "message": "Successfully established access to target Azure tenant via browser login",
                    "value": {
                        current_access.get("id", "N/A"): {
                            "subscription_name": current_access.get("name", "N/A"),
                            "subscription_id": current_access.get("id", "N/A"),
                            "home_tenant_id": current_access.get("homeTenantId", "N/A"),
                            "state": current_access.get("state", "N/A"),
                            "identity": current_access.get("user", {}).get("name", "N/A"),
                            "identity_type": current_access.get("user", {}).get("type", "N/A"),
                        }
                    }
                }

            return ExecutionStatus.PARTIAL_SUCCESS, {
                "message": "Azure browser login completed, but Halberd could not parse subscription details",
                "value": raw_response.stdout.strip()
            }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to establish access to Azure tenant via browser login"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "tenant_id": {
                "type": "str",
                "required": False,
                "default": None,
                "name": "Tenant ID (Optional)",
                "input_field_type": "text"
            },
            "allow_no_subscriptions": {
                "type": "bool",
                "required": False,
                "default": True,
                "name": "Allow No Subscriptions",
                "input_field_type": "bool"
            }
        }
