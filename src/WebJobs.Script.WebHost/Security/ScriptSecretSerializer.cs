// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Microsoft.Azure.WebJobs.Script.WebHost
{
    public static class ScriptSecretSerializer
    {
        private static List<IScriptSecretSerializer> _secretFormatters = new List<IScriptSecretSerializer>
        {
            new ScriptSecretSerializerV0(),
            new ScriptSecretSerializerV1()
        };

        private static IScriptSecretSerializer DefaultSerializer => GetSerializer(_secretFormatters.Max(i => i.SupportedFormatVersion));

        public static string SerializeFunctionSecrets(IList<Key> secrets) => DefaultSerializer.SerializeFunctionSecrets(secrets);

        public static string SerializeHostSecrets(HostSecrets secrets) => DefaultSerializer.SerializeHostSecrets(secrets);

        public static IList<Key> DeserializeFunctionSecrets(string secretsJson) => ResolveSerializerAndRun(secretsJson, (s, o) => s.DeserializeFunctionSecrets(o));

        public static HostSecrets DeserializeHostSecrets(string secretsJson) => ResolveSerializerAndRun(secretsJson, (s, o) => s.DeserializeHostSecrets(o));

        private static TResult ResolveSerializerAndRun<TResult>(string secretsJson, Func<IScriptSecretSerializer, JObject, TResult> func)
        {
            JObject secrets = JObject.Parse(secretsJson);
            int formatVersion = secrets.Value<int>("version");

            IScriptSecretSerializer serializer = GetSerializer(formatVersion);

            return func(serializer, secrets);
        }

        private static IScriptSecretSerializer GetSerializer(int formatVersion)
        {
            IScriptSecretSerializer serializer = _secretFormatters.FirstOrDefault(s => s.SupportedFormatVersion == formatVersion);

            if (serializer == null)
            {
                throw new FormatException("Invalid function secrets file format.");
            }

            return serializer;
        }
    }
}
