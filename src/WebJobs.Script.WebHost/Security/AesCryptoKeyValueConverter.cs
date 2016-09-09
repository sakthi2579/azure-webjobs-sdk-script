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

namespace Microsoft.Azure.WebJobs.Script.WebHost
{
    public sealed class AesCryptoKeyValueConverter : KeyValueConverter, IKeyValueWriter, IKeyValueReader
    {
        private readonly IEncryptionKeyResolver _keyResolver;

        public AesCryptoKeyValueConverter(FileAccess access)
            : this(new DefaultEncryptionKeyResolver(), access)
        {
        }

        public AesCryptoKeyValueConverter(IEncryptionKeyResolver keyResolver, FileAccess access)
            : base(access)
        {
            _keyResolver = keyResolver;
        }

        public string ReadValue(Key key)
        {
            ValidateAccess(FileAccess.Read);

            CryptographicKey cryptoKey = _keyResolver.ResolveKey(key.EncryptionKeyId);

            ValidateKey(cryptoKey);

            return DecryptValue(key.Value, cryptoKey.GetValue());
        }

        public Key WriteValue(Key key)
        {
            ValidateAccess(FileAccess.Write);

            CryptographicKey cryptoKey = _keyResolver.ResolveKey(key.EncryptionKeyId);

            ValidateKey(cryptoKey);

            string encryptedValue = EncryptValue(key.Value, cryptoKey.GetValue());

            return new Key
            {
                Name = key.Name,
                EncryptionKeyId = cryptoKey.Id,
                Value = encryptedValue,
                IsEncrypted = true
            };
        }

        private static void ValidateKey(CryptographicKey cryptoKey)
        {
            if (cryptoKey == null)
            {
                throw new CryptographicException("Missing key configuration.");
            }
        }

        private static string EncryptValue(string value, byte[] encryptionKey)
        {
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Key = encryptionKey;
                aes.GenerateIV();

                ICryptoTransform encryptor = aes.CreateEncryptor();

                using (var resultStream = new MemoryStream())
                {
                    // Write the IV to the stream (IV will prepend the encrypted data)
                    resultStream.Write(aes.IV, 0, aes.IV.Length);

                    using (var cryptoStream = new CryptoStream(resultStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (var writer = new StreamWriter(cryptoStream))
                        {
                            writer.Write(value);
                        }

                        return Convert.ToBase64String(resultStream.ToArray());
                    }
                }
            }
        }

        private static string DecryptValue(string value, byte[] encryptionKey)
        {
            using (var aes = new AesCryptoServiceProvider())
            {
                aes.Key = encryptionKey;

                byte[] encryptedData = Convert.FromBase64String(value);

                int blockSizeInBytes = aes.BlockSize / 8;
                byte[] iv = encryptedData.Take(blockSizeInBytes).ToArray();

                ICryptoTransform decryptor = aes.CreateDecryptor(encryptionKey, iv);

                using (var stream = new MemoryStream(encryptedData, blockSizeInBytes, encryptedData.Length - blockSizeInBytes))
                {
                    using (var cryptoStream = new CryptoStream(stream, decryptor, CryptoStreamMode.Read))
                    {
                        using (var writer = new StreamReader(cryptoStream))
                        {
                            return writer.ReadToEnd();
                        }
                    }
                }
            }
        }
    }
}
