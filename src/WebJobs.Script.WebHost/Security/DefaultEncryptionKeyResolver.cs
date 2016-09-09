// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using System.Collections;
using System.Globalization;
using System.IO;
using System.IO.Abstractions;
using System.Linq;
using System.Xml.Linq;
using System.Xml.XPath;

namespace Microsoft.Azure.WebJobs.Script.WebHost
{
    public class DefaultEncryptionKeyResolver : IEncryptionKeyResolver
    {
        internal const string DefaultEncryptionKeyId = "default";
        private const string MachingKeyXPathFormat = "configuration/location[@path='{0}']/system.web/machineKey/@decryptionKey";
        private static readonly string[] DefaultKeyIdMappings = new[] { null, string.Empty, DefaultEncryptionKeyId, EnvironmentSettingNames.AzureWebsiteEncryptionKey };
        private readonly IFileSystem _fileSystem;

        private CryptographicKey _defaultKey;

        public DefaultEncryptionKeyResolver()
            : this(new FileSystem())
        {
        }

        public DefaultEncryptionKeyResolver(IFileSystem fileSystem)
        {
            _fileSystem = fileSystem;
        }

        public CryptographicKey ResolveKey(string keyId) => IsDefaultKey(keyId) ? GetDefaultKey() : GetNamedKey(keyId);

        private static CryptographicKey GetNamedKey(string keyId)
        {
            string keyValue = Environment.GetEnvironmentVariable(keyId);
            if (keyValue != null)
            {
                return CryptographicKey.FromHexString(keyId, keyValue);
            }

            return null;
        }

        private CryptographicKey GetDefaultKey()
        {
            if (_defaultKey == null)
            {
                string keyId = Environment.GetEnvironmentVariable(EnvironmentSettingNames.AzureWebJobsDefaultEncryptionKeyId);

                if (keyId != null)
                {
                    return GetNamedKey(keyId);
                }

                string keyValue = null;
                if (WebScriptHostManager.IsAzureEnvironment)
                {
                    // If running in Azure, try to pull the key from the environment
                    // and fallback to config file if not available
                    keyValue = Environment.GetEnvironmentVariable(EnvironmentSettingNames.AzureWebsiteEncryptionKey) ?? GetMachineConfigKey();
                }
                else
                {
                    keyValue = Environment.GetEnvironmentVariable(EnvironmentSettingNames.AzureWebJobsLocalEncryptionKey);
                }

                if (keyValue != null)
                {
                    _defaultKey = CryptographicKey.FromHexString(DefaultEncryptionKeyId, keyValue);
                }
            }

            return _defaultKey;
        }

        private string GetMachineConfigKey()
        {
            // Load the rootweb.config file from the local config location.
            // This is temporary and should be removed once the encryption key is always
            // set as an environment variable in Azure.
            using (var reader = new StringReader(_fileSystem.File.ReadAllText(@"D:\local\config\rootweb.config")))
            {
                var xdoc = XDocument.Load(reader);

                string siteName = Environment.GetEnvironmentVariable(EnvironmentSettingNames.AzureWebsiteName);
                string xpath = string.Format(CultureInfo.InvariantCulture, MachingKeyXPathFormat, siteName);

                return ((IEnumerable)xdoc.XPathEvaluate(xpath)).Cast<XAttribute>().FirstOrDefault()?.Value;
            }
        }

        private static bool IsDefaultKey(string keyName) => DefaultKeyIdMappings.Contains(keyName, StringComparer.OrdinalIgnoreCase);
    }
}
