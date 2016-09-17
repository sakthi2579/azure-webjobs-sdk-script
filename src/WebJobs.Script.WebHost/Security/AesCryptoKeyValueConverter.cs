// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Azure.Web.Cryptography;

namespace Microsoft.Azure.WebJobs.Script.WebHost
{
    public sealed class AesCryptoKeyValueConverter : KeyValueConverter, IKeyValueWriter, IKeyValueReader
    {
        private readonly CryptoUtility _cryptoUtility;

        public AesCryptoKeyValueConverter(FileAccess access)
            : base(access)
        {
            _cryptoUtility = new CryptoUtility();
        }

        public string ReadValue(Key key)
        {
            ValidateAccess(FileAccess.Read);

            return _cryptoUtility.DecryptValue(key.Value, key.EncryptionKeyId);
        }

        public Key WriteValue(Key key)
        {
            ValidateAccess(FileAccess.Write);

            EncryptionResult encryptedValue = _cryptoUtility.EncryptValue(key.Value, key.EncryptionKeyId);

            return new Key
            {
                Name = key.Name,
                EncryptionKeyId = encryptedValue.KeyId,
                Value = encryptedValue.Value,
                IsEncrypted = true
            };
        }
    }
}
