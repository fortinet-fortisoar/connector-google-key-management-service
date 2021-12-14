# connector-google-key-management-service

Google Key Management Service allows you to create, import, and manage cryptographic keys and perform cryptographic operations in a single centralized cloud service. This connector facilitates the automated operations related to location, keyRings, cryptoKey and cryptoKey version.

## API Documentation Link: https://cloud.google.com/kms/docs/reference/rest

## Google Key Management Service(KMS) Version: v1

# Accessing the Cloud Key Management Service(KMS) API

Google Key Management Service(KMS) in Google Cloud Platform uses OAuth 2.0 for API authentication and authorization. Authentication is the process of determining your identity. The OAuth Client ID and Client Secret are used to identify your app to Google’s OAuth servers. Authorization is the process of determining what permissions your app has against a set of resources.

You can follow the steps below to secure the authentication and authorization codes in order to access the Cloud Storage API:

1.  Create a project in Google Cloud. For more information on how to create a project, see Creating and managing projects.
2.  Inside your project, create the Client ID and Client Secret for your app. Once created, you can access the Client ID and Client Secret from the Credentials section of your project in Google Cloud Console. Make a note of these authentication credentials as you will need to copy them over to your FortiSOAR™ instance momentarily.
3.  Enable the Cloud Key Management Service API for your app. See Enabling APIs for more information.
4.  Back in FortiSOAR™, go to the Configurations tab of the Google Key Management Service connector, and enter the authentication details in the following fields in order to authenticate the Google Key Management Service Connector with the Cloud Key Management Service API:

* In the Client ID field, enter the client ID
* In the Client Secret field, enter the client secret
* In the Redirect URL field, enter the redirect URI. By default, the redirect URI is set to https://localhost/myapp

5.    Now that you have the authentication codes, you can use them to generate the authorization code. Copy the following URL into a browser and replace the CLIENT_ID and REDIRECT_URI with your project's client ID and redirect URI: https://accounts.google.com/o/oauth2/v2/auth?scope=https://www.googleapis.com/auth/cloud-platform&access_type=offline&include_granted_scopes=true&response_type=code&state=state_parameter_passthrough_value&redirect_uri=REDIRECT_URI&client_id=CLIENT_ID
6.    OAuth 2.0 uses scopes to define the permissions of your authenticated app. If your app does not have the required scope, you will be prompted to provide the cloud-platform scope to your application. The cloud-platform scope allows you to view and manage data across all Google Cloud services.
7.  Next, you will be automatically redirected to a link with the following structure: REDIRECT_URI?state=STATE&code=AUTH_CODE&scope=SCOPE. Copy the AUTH_CODE, and in the Configurations tab of the connector, paste the AUTH_CODE in the Authorization Code field.


The process to access the Cloud Key Management Service API is now complete.
