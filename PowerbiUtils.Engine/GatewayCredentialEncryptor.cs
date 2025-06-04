using System.Linq;
using System.Diagnostics.Contracts;
using System.Management.Automation;
using Microsoft.PowerBI.Api.Extensions;
using Microsoft.PowerBI.Api.Models;
using Microsoft.PowerBI.Api.Models.Credentials;
using Newtonsoft.Json;

namespace PowerbiUtils.Engine
{
    public class GatewayCredentialEncryptor
    {
        public static string encrypt(string gatewayKeyExponent, string gatewayKeyModulus, PSCredential credential)
        {
            var encryptor = new AsymmetricKeyEncryptor(new GatewayPublicKey(
                gatewayKeyExponent,
                gatewayKeyModulus
            ));

            var windowsCredentials = new WindowsCredentials(
                credential.UserName,
                credential.GetNetworkCredential().Password
            );

            var credentialsRequest = new CredentialsRequest
            {
                CredentialData = windowsCredentials.CredentialData.Select((pair) => new NameValuePair(pair.Key, pair.Value))
            };

            var credentialsJson = JsonConvert.SerializeObject(credentialsRequest);
            return encryptor.EncodeCredentials(credentialsJson);
            
        }
    }    
}
