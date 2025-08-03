<#

PSWaaS

Copyright (C) 2025 Vincent Anso

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.


For more information :

WaaS Assessment Platform

https://learn.microsoft.com/en-us/windows/win32/sysinfo/update-assessor-service

#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

using namespace System.Text
using namespace System.ComponentModel
using namespace System.Runtime.InteropServices
using namespace WaaSAssessment

# When $IsWindows doesn't exist on PowerShell 5.x
if ($null -eq $PSVersionTable.Platform) 
{
    $IsWindows = $true
}

if ( -Not $IsWindows )
{
    Write-Warning "This module only runs on Windows."
    exit 0
}

$sourceCode = @"
using System;
using System.Text;
using System.Runtime.InteropServices;
using FILETIME = System.Runtime.InteropServices.ComTypes.FILETIME;

namespace WaaSAssessment
{
    public static class Win32
    {
        public const uint LOCALE_USER_DEFAULT = 0x0400;

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEMTIME
        {
            public ushort wYear;
            public ushort wMonth;
            public ushort wDayOfWeek;
            public ushort wDay;
            public ushort wHour;
            public ushort wMinute;
            public ushort wSecond;
            public ushort wMilliseconds;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FileTimeToSystemTime(ref FILETIME fileTime, out SYSTEMTIME systemTime);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int GetDateFormat(uint locale, uint flags, ref SYSTEMTIME systemTime, string format, StringBuilder dateStr, int dateSize);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int GetTimeFormat(uint locale, uint flags, ref SYSTEMTIME systemTime, string format, StringBuilder timeStr, int timeSize);
    }

    // Define the COM interface IWaaSAssessor
    [ComImport]
    [Guid("2347bbef-1a3b-45a4-902d-3e09c269b45e")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IWaaSAssessor
    {
        int GetOSUpdateAssessment(ref OSUpdateAssessment result);
    }

    // Define the COM class WaaSAssessor
    [ComImport]
    [Guid("098ef871-fa9f-46af-8958-c083515d7c9c")]
    [ClassInterface(ClassInterfaceType.None)]
    public class WaaSAssessor
    {
    }

    // Enum representation of UpdateImpactLevel
    public enum UpdateImpactLevel : uint
    {
        None = 0,
        Low = None + 1,
        Medium = Low + 1,
        High = Medium + 1
    }

    // Enum representation of UpdateAssessmentStatus
    public enum UpdateAssessmentStatus : uint
    {
        Latest = 0,
        NotLatestSoftRestriction = Latest + 1,
        NotLatestHardRestriction = NotLatestSoftRestriction + 1,
        NotLatestEndOfSupport = NotLatestHardRestriction + 1,
        NotLatestServicingTrain = NotLatestEndOfSupport + 1,
        NotLatestDeferredFeature = NotLatestServicingTrain + 1,
        NotLatestDeferredQuality = NotLatestDeferredFeature + 1,
        NotLatestPausedFeature = NotLatestDeferredQuality + 1,
        NotLatestPausedQuality = NotLatestPausedFeature + 1,
        NotLatestManaged = NotLatestPausedQuality + 1,
        NotLatestUnknown = NotLatestManaged + 1,
        NotLatestTargetedVersion = NotLatestUnknown + 1
    }

    // Struct representation of UpdateAssessment
    [StructLayout(LayoutKind.Sequential)]
    public struct UpdateAssessment
    {
        public UpdateAssessmentStatus Status;
        public UpdateImpactLevel Impact;
        public uint DaysOutOfDate;
    }

    // Struct representation of OSUpdateAssessment
    [StructLayout(LayoutKind.Sequential)]
    public struct OSUpdateAssessment
    {
        [MarshalAs(UnmanagedType.Bool)]
        public bool IsEndOfSupport;
        public UpdateAssessment AssessmentForCurrent;
        public UpdateAssessment AssessmentForUpToDate;
        public UpdateAssessmentStatus SecurityStatus;
        public FILETIME AssessmentTime;
        public FILETIME ReleaseInfoTime;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string CurrentOSBuild;
        public FILETIME CurrentOSReleaseTime;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string UpToDateOSBuild;
        public FILETIME UpToDateOSReleaseTime;
    }

    public static class WaaSAssessorHelper
    {
        public static int GetOSUpdateAssessment(ref OSUpdateAssessment result)
        {
            IWaaSAssessor assessor = null;

            try
            {
                assessor = (IWaaSAssessor)new WaaSAssessor();
                int hr = assessor.GetOSUpdateAssessment(ref result);
                return hr;
            }
            catch (Exception ex)
            {
                return ex.HResult;
            }
        }
    }
}
"@

Add-Type -TypeDefinition $sourceCode

function ConvertFrom-FILETIME
{
      param (
        [Parameter(Mandatory = $true)]
        [ComTypes.FILETIME]$FileTime
    )

    $invalidDate = [DateTime]::new(1601, 1, 1)

    $systemTime = New-Object Win32+SYSTEMTIME
        
    if ( [Win32]::FileTimeToSystemTime([ref]$FileTime, [ref]$systemTime) )
    {
        $currentCulture = Get-Culture
        
        $shortDatePattern = $currentCulture.DateTimeFormat.ShortDatePattern
        $longTimePattern = $currentCulture.DateTimeFormat.LongTimePattern

        $dateBuffer = [StringBuilder]::new()
        $timeBuffer = [StringBuilder]::new()

        $dateSize = [Win32]::GetDateFormat([Win32]::LOCALE_USER_DEFAULT, 0, [ref]$systemTime, $shortDatePattern, $dateBuffer, $dateBuffer.Capacity)
        $timeSize = [Win32]::GetTimeFormat([Win32]::LOCALE_USER_DEFAULT, 0, [ref]$systemTime, $longTimePattern , $timeBuffer, $timeBuffer.Capacity)

        $dateTime = [DateTime]::new(0)

        if ( [DateTime]::TryParse("$dateBuffer $timeBuffer", [ref]$dateTime) )
        {
            if ( $dateTime -gt $( [DateTime]::new(2006, 11, 14) ) )
            {
                return $dateTime
            }
        }
    }
    return $invalidDate
}

function Get-OSUpdateAssessment
{
    <#
    
    .SYNOPSIS
    Gets WaaS Assessment Platform information.

    #>
    
    param(
        [switch]$Raw
    )
    
    $result = [OSUpdateAssessment]::new()

    $hr = [WaaSAssessorHelper]::GetOSUpdateAssessment([ref]$result)

    if ($hr -ne 0x0)
    {
        [Win32Exception]::new($hr)

        exit $hr
    }

    if ( $PSBoundParameters.ContainsKey("Raw") )
    {
        $result
    }
    else 
    {
        [PSCustomObject]@{
        IsEndOfSupport        = $result.IsEndOfSupport
        AssessmentForCurrent  = @{ Status     = $result.AssessmentForCurrent.Status
                                Impact        = $result.AssessmentForCurrent.Impact
                                DaysOutOfDate = $result.AssessmentForCurrent.DaysOutOfDate
                                }    
        AssessmentForUpToDate = @{ Status     = $result.AssessmentForUpToDate.Status
                                Impact        = $result.AssessmentForUpToDate.Impact
                                DaysOutOfDate = $result.AssessmentForUpToDate.DaysOutOfDate
                                }  
        SecurityStatus        = $result.SecurityStatus
        AssessmentTime        = ConvertFrom-FILETIME $result.AssessmentTime
        ReleaseInfoTime       = ConvertFrom-FILETIME $result.ReleaseInfoTime
        CurrentOSBuild        = [Version]$result.CurrentOSBuild
        CurrentOSReleaseTime  = ConvertFrom-FILETIME $result.CurrentOSReleaseTime
        UpToDateOSBuild       = [Version]$result.UpToDateOSBuild
        UpToDateOSReleaseTime = ConvertFrom-FILETIME $result.UpToDateOSReleaseTime
        }
    }
}

Export-ModuleMember -Function @('Get-OSUpdateAssessment')
