// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System.Threading.Tasks;

namespace Microsoft.Azure.WebJobs.Script.WebHost
{
    public sealed class PlaintextKeyValueConverter : IKeyValueConverter
    {
        public string ReadKeyValue(Key key)
        {
            return key.Value;
        }

        public Key WriteKeyValue(Key key) => new Key(key.Name, key.Value);
    }
}
