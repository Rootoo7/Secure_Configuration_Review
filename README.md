# Secure_Configuration_Review

This PowerShell script performs a comprehensive review of Active Directory based on CIS benchmarks and additional security checks. It outputs the results to an HTML file (ADreview.html) that includes observations, severity, domain assessed, impact of the issue, and recommendations to fix the identified issues.

Script Overview
The script checks the following aspects of Active Directory:

Domain and Forest Functional Levels
Users with Delegated Permissions
Expired User Accounts
Disabled User Accounts
Locked Out User Accounts
User Accounts with No Password Expiry
User Accounts with Passwords Not Required
User Accounts with Admin Privileges
Computer Accounts Not Used in Last 90 Days
Group Policy Objects (GPOs) not Linked
Additionally, it includes the following security checks:

Kerberoast Vulnerability
Kerberos Account Password Age
Obsolete Operating Systems
Outdated Domain Controllers
Non-Admin Users' Ability to Add Users to the Domain
Local Administrator Password Solution (LAPS) Installation
Output Format
The script generates an HTML report (ADreview.html) structured as follows:

Observation: Description of the issue identified.
Severity: Impact level of the issue (Low, Moderate, High).
Domain Assessed: Domain where the issue was identified.
Impact: Potential impact of the identified issue on security.
Recommendation: Recommendations to mitigate or fix the identified issues.

Usage
Prerequisites:

Ensure PowerShell is run with administrator privileges.
Permissions to access Active Directory components.
Execution:

Run the script (ADreview.ps1) using PowerShell.
Review the generated HTML report (ADreview.html) for detailed findings.
Review and Action:

Review each observation in the HTML report.
Implement recommended actions to improve Active Directory security.
Notes
Safety: The script is designed to gather information without making any changes to the Active Directory environment.
Customization: Modify the script as needed to suit specific organizational requirements or additional checks.
