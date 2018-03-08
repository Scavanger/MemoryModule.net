/*                                                               
 * Memory Module.net 0.2
 * 
 * Loading a native Dll from memory, a C#/.net port of Memory Module
 * 
 * (c) 2012-2018 by Andreas Kanzler (andi_kanzler(at)gmx.de)
 * 
 * Memory Module is original developed by Joachim Bauch (mail(at)joachim-bauch.de)  
 * https://github.com/fancycode/MemoryModule
 * http://www.joachim-bauch.de/tutorials/loading-a-dll-from-memory/                
 *                                                                                
 * 
 * The contents of this file are subject to the Mozilla Public License Version
 * 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is MemoryModule.c
 *
 * The Initial Developer of the Original Code is Joachim Bauch.
 *
 * Portions created by Andreas Kanzler are Copyright (c)2012
 * Andreas Kanzler. All Rights Reserved.
 * 
 */

using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Scavanger.MemoryModule
{
    public class NativeDllLoadException : Exception
    {
        public Win32Exception Win32Exception { get; private set; } 

        public NativeDllLoadException()
            : base()
        {
            Win32Exception = new Win32Exception();
        }

        public NativeDllLoadException(string message)
            : base(message)
        {
            Win32Exception = new Win32Exception();
        }

        public NativeDllLoadException(string message, Exception innerException)
            : base(message, innerException)
        {
            Win32Exception = new Win32Exception();
        }
    }
}
