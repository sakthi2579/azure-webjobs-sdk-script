// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Azure.WebJobs.Script.WebHost
{
    public sealed class DefaultKeyValueConverterFactory : IKeyValueConverterFactory
    {
        private static readonly PlainTextKeyValueConverter PlainTextConverter = new PlainTextKeyValueConverter();

        public IKeyValueConverter GetValueConverter(Key key, KeyConversionAction action)
        {
            return PlainTextConverter;
        }
    }
}
