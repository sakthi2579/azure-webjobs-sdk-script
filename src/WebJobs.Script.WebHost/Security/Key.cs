﻿// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using System.Runtime.CompilerServices;
using Newtonsoft.Json;

namespace Microsoft.Azure.WebJobs.Script.WebHost
{
    public class Key : IEquatable<Key>
    {
        public Key()
        {
        }

        public Key(string name, string value)
        {
            Name = name;
            Value = value;
        }

        [JsonProperty(PropertyName = "name")]
        public string Name { get; set; }

        [JsonProperty(PropertyName = "value")]
        public string Value { get; set; }

        [JsonProperty(PropertyName = "encrypted")]
        public bool IsEncrypted { get; set; }

        [JsonProperty(PropertyName = "encryptionKeyId")]
        public string EncryptionKeyId { get; set; }

        public bool Equals(Key other)
        {
            if (other == null)
            {
                return false;
            }

            return string.Equals(Name, other.Name, StringComparison.Ordinal) &&
                SecretValueEquals(Value, other.Value) &&
                string.Equals(EncryptionKeyId, other.EncryptionKeyId, StringComparison.Ordinal) &&
                IsEncrypted == other.IsEncrypted;
        }

        public override bool Equals(object obj) => Equals(obj as Key);

        /// <summary>
        /// Provides a time consistent comparison of two secrets in the form of two strings.
        /// This prevents security attacks that attempt to determine key values based on response
        /// times.
        /// </summary>
        /// <param name="inputA">The first secret to compare.</param>
        /// <param name="inputB">The second secret to compare.</param>
        /// <returns>Returns <c>true</c> if the two secrets are equal, <c>false</c> otherwise.</returns>
        [MethodImpl(MethodImplOptions.NoOptimization)]
        public static bool SecretValueEquals(string inputA, string inputB)
        {
            if (ReferenceEquals(inputA, inputB))
            {
                return true;
            }

            if (inputA == null || inputB == null || inputA.Length != inputB.Length)
            {
                return false;
            }

            bool areSame = true;
            for (int i = 0; i < inputA.Length; i++)
            {
                areSame &= inputA[i] == inputB[i];
            }

            return areSame;
        }

        public override int GetHashCode() => GetPropertyHashCode(Name) ^ GetPropertyHashCode(Value) ^ GetPropertyHashCode(EncryptionKeyId) ^ IsEncrypted.GetHashCode();

        private static int GetPropertyHashCode(string value) => value?.GetHashCode() ?? 0;
    }
}