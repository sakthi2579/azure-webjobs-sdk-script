// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace Microsoft.Azure.Web.Cryptography
{
    public class CryptoUtility
    {
        private readonly IEncryptionKeyResolver _keyResolver;

        public CryptoUtility()
            : this(new DefaultEncryptionKeyResolver())
        {
        }

        public CryptoUtility(IEncryptionKeyResolver keyResolver)
        {
            _keyResolver = keyResolver;
        }

        public EncryptionResult EncryptValue(string value, string keyId = null)
        {
            CryptographicKey cryptoKey = GetEncryptionKey(keyId);

            string encryptedValue = EncryptValue(value, cryptoKey.GetValue());

            return new EncryptionResult(cryptoKey.Id, encryptedValue);
        }

        public string DecryptValue(string value, string keyId = null)
        {
            CryptographicKey cryptoKey = GetEncryptionKey(keyId);

            return DecryptValue(value, cryptoKey.GetValue());
        }

        private CryptographicKey GetEncryptionKey(string keyId, bool throwIfNotFound = true)
        {
            CryptographicKey cryptoKey = _keyResolver.ResolveKey(keyId);

            if (throwIfNotFound && cryptoKey == null)
            {
                throw new CryptographicException($"Missing key configuration. (Key id: {keyId}");
            }

            return cryptoKey;
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
