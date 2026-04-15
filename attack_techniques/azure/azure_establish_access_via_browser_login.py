from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, AzureTRMTechnique, TechniqueReference, TechniqueNote
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.azure.azure_access import AzureAccess
import os


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
            TechniqueNote("This technique reuses an existing Azure CLI browser login instead of trying to launch a browser flow invisibly inside Halberd."),
            TechniqueNote("When Halberd runs in Docker, mount your host Azure CLI config directory into the container so the existing Azure session is visible to the app."),
            TechniqueNote("Run az login on the host first, then use this technique to validate and import the active Azure CLI session into Halberd.")
        ]

        super().__init__(
            "Establish Access via Browser Login",
            "Reuses an existing Azure CLI browser-authenticated session for MFA-enabled Azure user accounts. This technique is intended for environments where username/password authentication is unsupported and device code flow may be restricted by Conditional Access. Run az login on the host first, ensure the Azure CLI config is available to Halberd, then use this technique to validate and display the active Azure session for follow-on Azure techniques.",
            mitre_techniques,
            azure_trm_technique,
            references=technique_references,
            notes=technique_notes
        )

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)

        try:
            tenant_id: str = kwargs.get("tenant_id", None)
            subscription_id: str = kwargs.get("subscription_id", None)
            runtime_profile: str = kwargs.get("runtime_profile", "docker_macos_linux")
            azure_access = AzureAccess()

            if not azure_access.az_command:
                return ExecutionStatus.FAILURE, {
                    "error": "Azure CLI not found",
                    "message": "Azure CLI is not installed or not accessible"
                }

            azure_config_dir = os.environ.get("AZURE_CONFIG_DIR", "Not set")
            current_access = azure_access.get_current_subscription_info()

            if current_access is None:
                guidance = self._build_guidance(runtime_profile, tenant_id, subscription_id)

                return ExecutionStatus.FAILURE, {
                    "error": {
                        "azure_config_dir": azure_config_dir,
                        "runtime_profile": runtime_profile,
                        "guidance": guidance
                    },
                    "message": "No reusable Azure browser-authenticated session is currently available to Halberd"
                }

            if tenant_id not in [None, ""] and current_access.get("tenantId") not in [tenant_id, None]:
                return ExecutionStatus.FAILURE, {
                    "error": {
                        "expected_tenant_id": tenant_id,
                        "active_tenant_id": current_access.get("tenantId"),
                        "azure_config_dir": azure_config_dir,
                        "runtime_profile": runtime_profile
                    },
                    "message": "An Azure CLI session exists, but it is authenticated to a different tenant than requested"
                }

            if subscription_id not in [None, ""] and current_access.get("id") not in [subscription_id, None]:
                return ExecutionStatus.FAILURE, {
                    "error": {
                        "expected_subscription_id": subscription_id,
                        "active_subscription_id": current_access.get("id"),
                        "azure_config_dir": azure_config_dir,
                        "runtime_profile": runtime_profile,
                        "guidance": self._build_guidance(runtime_profile, tenant_id, subscription_id)
                    },
                    "message": "An Azure CLI session exists, but it is using a different subscription than requested"
                }

            return ExecutionStatus.SUCCESS, {
                "message": "Successfully established access to target Azure tenant via existing browser-authenticated Azure CLI session",
                "value": {
                    current_access.get("id", "N/A"): {
                        "subscription_name": current_access.get("name", "N/A"),
                        "subscription_id": current_access.get("id", "N/A"),
                        "home_tenant_id": current_access.get("homeTenantId", "N/A"),
                        "state": current_access.get("state", "N/A"),
                        "identity": current_access.get("user", {}).get("name", "N/A"),
                        "identity_type": current_access.get("user", {}).get("type", "N/A"),
                        "tenant_id": current_access.get("tenantId", "N/A"),
                        "azure_config_dir": azure_config_dir,
                        "runtime_profile": runtime_profile
                    }
                }
            }

        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to establish access to Azure tenant via browser login"
            }

    def get_parameters(self) -> Dict[str, Dict[str, Any]]:
        return {
            "runtime_profile": {
                "type": "str",
                "required": False,
                "default": "docker_macos_linux",
                "name": "Deployment Environment",
                "input_field_type": "select",
                "input_list": [
                    {"label": "Docker on Mac/Linux", "value": "docker_macos_linux"},
                    {"label": "Docker on Windows VDI", "value": "docker_windows_vdi"}
                ],
                "description": "Used to tailor the Azure login guidance shown by Halberd"
            },
            "tenant_id": {
                "type": "str",
                "required": False,
                "default": None,
                "name": "Tenant ID (Optional)",
                "description": "Enter this if the Azure login must land in a specific tenant",
                "input_field_type": "text"
            },
            "subscription_id": {
                "type": "str",
                "required": False,
                "default": None,
                "name": "Subscription ID (Optional)",
                "description": "Enter this if the Azure login must use a specific subscription",
                "input_field_type": "text"
            }
        }

    @staticmethod
    def _build_guidance(runtime_profile: str, tenant_id: str = None, subscription_id: str = None) -> list[str]:
        login_command = "az login"
        if tenant_id not in [None, ""]:
            login_command = f"az login --tenant {tenant_id}"

        subscription_step = f"Run `az account set --subscription {subscription_id}`." if subscription_id not in [None, ""] else "Run `az account list --all -o table` and identify the correct subscription ID, then run `az account set --subscription <subscription-id>`."

        profile_guidance = {
            "docker_macos_linux": [
                "No active Azure CLI session is visible to Halberd.",
                f"On your Mac/Linux host, run `{login_command}` and complete the full browser and MFA sequence.",
                subscription_step,
                "Run `az account show` and confirm it returns the expected tenant and subscription.",
                "Halberd in Docker must be able to read the host Azure CLI profile via the mount `${HOME}/.azure:/home/halberd/.azure`."
            ],
            "docker_windows_vdi": [
                "No active Azure CLI session is visible to Halberd.",
                "On the Windows VDI host, first run `az config set core.enable_broker_on_windows=false` if WAM-based login is not reusable from Docker.",
                f"Then run `{login_command}` and complete the full browser and MFA sequence.",
                subscription_step,
                "Run `az account show` and confirm it returns the expected tenant and subscription.",
                "Halberd in Docker must be able to read the host Azure CLI profile via the mount `${USERPROFILE}/.azure:/home/halberd/.azure`."
            ]
        }

        return profile_guidance.get(runtime_profile, profile_guidance["docker_macos_linux"])
