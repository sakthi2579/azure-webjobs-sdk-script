// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Azure.Web.Cryptography
{
    public class EncryptionResult
    {
        public EncryptionResult(string keyId, string value)
        {
            KeyId = keyId;
            Value = value;
        }

        public string KeyId { get; }

        public string Value { get; }
    }
}
