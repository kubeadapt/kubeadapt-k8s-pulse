// Copyright 2013-2023 The Cobra Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// The generated scripts require PowerShell v5.0+ (which comes Windows 10, but
// can be downloaded separately for windows 7 or 8.1).

package cobra

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
)

func genPowerShellComp(buf io.StringWriter, name string, includeDesc bool) {
	// Variables should not contain a '-' or ':' character
	nameForVar := name
	nameForVar = strings.ReplaceAll(nameForVar, "-", "_")
	nameForVar = strings.ReplaceAll(nameForVar, ":", "_")

	compCmd := ShellCompRequestCmd
	if !includeDesc {
		compCmd = ShellCompNoDescRequestCmd
	}
	WriteStringAndCheck(buf, fmt.Sprintf(`***REMOVED*** powershell completion for %-36[1]s -*- shell-script -*-

function __%[1]s_debug {
    if ($env:BASH_COMP_DEBUG_FILE) {
        "$args" | Out-File -Append -FilePath "$env:BASH_COMP_DEBUG_FILE"
    }
}

filter __%[1]s_escapeStringWithSpecialChars {
`+"    $_ -replace '\\s|***REMOVED***|@|\\$|;|,|''|\\{|\\}|\\(|\\)|\"|`|\\||<|>|&','`$&'"+`
}

[scriptblock]${__%[2]sCompleterBlock} = {
    param(
            $WordToComplete,
            $CommandAst,
            $CursorPosition
        )

    ***REMOVED*** Get the current command line and convert into a string
    $Command = $CommandAst.CommandElements
    $Command = "$Command"

    __%[1]s_debug ""
    __%[1]s_debug "========= starting completion logic =========="
    __%[1]s_debug "WordToComplete: $WordToComplete Command: $Command CursorPosition: $CursorPosition"

    ***REMOVED*** The user could have moved the cursor backwards on the command-line.
    ***REMOVED*** We need to trigger completion from the $CursorPosition location, so we need
    ***REMOVED*** to truncate the command-line ($Command) up to the $CursorPosition location.
    ***REMOVED*** Make sure the $Command is longer then the $CursorPosition before we truncate.
    ***REMOVED*** This happens because the $Command does not include the last space.
    if ($Command.Length -gt $CursorPosition) {
        $Command=$Command.Substring(0,$CursorPosition)
    }
    __%[1]s_debug "Truncated command: $Command"

    $ShellCompDirectiveError=%[4]d
    $ShellCompDirectiveNoSpace=%[5]d
    $ShellCompDirectiveNoFileComp=%[6]d
    $ShellCompDirectiveFilterFileExt=%[7]d
    $ShellCompDirectiveFilterDirs=%[8]d
    $ShellCompDirectiveKeepOrder=%[9]d

    ***REMOVED*** Prepare the command to request completions for the program.
    ***REMOVED*** Split the command at the first space to separate the program and arguments.
    $Program,$Arguments = $Command.Split(" ",2)

    $RequestComp="$Program %[3]s $Arguments"
    __%[1]s_debug "RequestComp: $RequestComp"

    ***REMOVED*** we cannot use $WordToComplete because it
    ***REMOVED*** has the wrong values if the cursor was moved
    ***REMOVED*** so use the last argument
    if ($WordToComplete -ne "" ) {
        $WordToComplete = $Arguments.Split(" ")[-1]
    }
    __%[1]s_debug "New WordToComplete: $WordToComplete"


    ***REMOVED*** Check for flag with equal sign
    $IsEqualFlag = ($WordToComplete -Like "--*=*" )
    if ( $IsEqualFlag ) {
        __%[1]s_debug "Completing equal sign flag"
        ***REMOVED*** Remove the flag part
        $Flag,$WordToComplete = $WordToComplete.Split("=",2)
    }

    if ( $WordToComplete -eq "" -And ( -Not $IsEqualFlag )) {
        ***REMOVED*** If the last parameter is complete (there is a space following it)
        ***REMOVED*** We add an extra empty parameter so we can indicate this to the go method.
        __%[1]s_debug "Adding extra empty parameter"
        ***REMOVED*** PowerShell 7.2+ changed the way how the arguments are passed to executables,
        ***REMOVED*** so for pre-7.2 or when Legacy argument passing is enabled we need to use
`+"        ***REMOVED*** `\"`\" to pass an empty argument, a \"\" or '' does not work!!!"+`
        if ($PSVersionTable.PsVersion -lt [version]'7.2.0' -or
            ($PSVersionTable.PsVersion -lt [version]'7.3.0' -and -not [ExperimentalFeature]::IsEnabled("PSNativeCommandArgumentPassing")) -or
            (($PSVersionTable.PsVersion -ge [version]'7.3.0' -or [ExperimentalFeature]::IsEnabled("PSNativeCommandArgumentPassing")) -and
              $PSNativeCommandArgumentPassing -eq 'Legacy')) {
`+"             $RequestComp=\"$RequestComp\" + ' `\"`\"'"+`
        } else {
             $RequestComp="$RequestComp" + ' ""'
        }
    }

    __%[1]s_debug "Calling $RequestComp"
    ***REMOVED*** First disable ActiveHelp which is not supported for Powershell
    ${env:%[10]s}=0

    ***REMOVED***call the command store the output in $out and redirect stderr and stdout to null
    ***REMOVED*** $Out is an array contains each line per element
    Invoke-Expression -OutVariable out "$RequestComp" 2>&1 | Out-Null

    ***REMOVED*** get directive from last line
    [int]$Directive = $Out[-1].TrimStart(':')
    if ($Directive -eq "") {
        ***REMOVED*** There is no directive specified
        $Directive = 0
    }
    __%[1]s_debug "The completion directive is: $Directive"

    ***REMOVED*** remove directive (last element) from out
    $Out = $Out | Where-Object { $_ -ne $Out[-1] }
    __%[1]s_debug "The completions are: $Out"

    if (($Directive -band $ShellCompDirectiveError) -ne 0 ) {
        ***REMOVED*** Error code.  No completion.
        __%[1]s_debug "Received error from custom completion go code"
        return
    }

    $Longest = 0
    [Array]$Values = $Out | ForEach-Object {
        ***REMOVED***Split the output in name and description
`+"        $Name, $Description = $_.Split(\"`t\",2)"+`
        __%[1]s_debug "Name: $Name Description: $Description"

        ***REMOVED*** Look for the longest completion so that we can format things nicely
        if ($Longest -lt $Name.Length) {
            $Longest = $Name.Length
        }

        ***REMOVED*** Set the description to a one space string if there is none set.
        ***REMOVED*** This is needed because the CompletionResult does not accept an empty string as argument
        if (-Not $Description) {
            $Description = " "
        }
        @{Name="$Name";Description="$Description"}
    }


    $Space = " "
    if (($Directive -band $ShellCompDirectiveNoSpace) -ne 0 ) {
        ***REMOVED*** remove the space here
        __%[1]s_debug "ShellCompDirectiveNoSpace is called"
        $Space = ""
    }

    if ((($Directive -band $ShellCompDirectiveFilterFileExt) -ne 0 ) -or
       (($Directive -band $ShellCompDirectiveFilterDirs) -ne 0 ))  {
        __%[1]s_debug "ShellCompDirectiveFilterFileExt ShellCompDirectiveFilterDirs are not supported"

        ***REMOVED*** return here to prevent the completion of the extensions
        return
    }

    $Values = $Values | Where-Object {
        ***REMOVED*** filter the result
        $_.Name -like "$WordToComplete*"

        ***REMOVED*** Join the flag back if we have an equal sign flag
        if ( $IsEqualFlag ) {
            __%[1]s_debug "Join the equal sign flag back to the completion value"
            $_.Name = $Flag + "=" + $_.Name
        }
    }

    ***REMOVED*** we sort the values in ascending order by name if keep order isn't passed
    if (($Directive -band $ShellCompDirectiveKeepOrder) -eq 0 ) {
        $Values = $Values | Sort-Object -Property Name
    }

    if (($Directive -band $ShellCompDirectiveNoFileComp) -ne 0 ) {
        __%[1]s_debug "ShellCompDirectiveNoFileComp is called"

        if ($Values.Length -eq 0) {
            ***REMOVED*** Just print an empty string here so the
            ***REMOVED*** shell does not start to complete paths.
            ***REMOVED*** We cannot use CompletionResult here because
            ***REMOVED*** it does not accept an empty string as argument.
            ""
            return
        }
    }

    ***REMOVED*** Get the current mode
    $Mode = (Get-PSReadLineKeyHandler | Where-Object {$_.Key -eq "Tab" }).Function
    __%[1]s_debug "Mode: $Mode"

    $Values | ForEach-Object {

        ***REMOVED*** store temporary because switch will overwrite $_
        $comp = $_

        ***REMOVED*** PowerShell supports three different completion modes
        ***REMOVED*** - TabCompleteNext (default windows style - on each key press the next option is displayed)
        ***REMOVED*** - Complete (works like bash)
        ***REMOVED*** - MenuComplete (works like zsh)
        ***REMOVED*** You set the mode with Set-PSReadLineKeyHandler -Key Tab -Function <mode>

        ***REMOVED*** CompletionResult Arguments:
        ***REMOVED*** 1) CompletionText text to be used as the auto completion result
        ***REMOVED*** 2) ListItemText   text to be displayed in the suggestion list
        ***REMOVED*** 3) ResultType     type of completion result
        ***REMOVED*** 4) ToolTip        text for the tooltip with details about the object

        switch ($Mode) {

            ***REMOVED*** bash like
            "Complete" {

                if ($Values.Length -eq 1) {
                    __%[1]s_debug "Only one completion left"

                    ***REMOVED*** insert space after value
                    [System.Management.Automation.CompletionResult]::new($($comp.Name | __%[1]s_escapeStringWithSpecialChars) + $Space, "$($comp.Name)", 'ParameterValue', "$($comp.Description)")

                } else {
                    ***REMOVED*** Add the proper number of spaces to align the descriptions
                    while($comp.Name.Length -lt $Longest) {
                        $comp.Name = $comp.Name + " "
                    }

                    ***REMOVED*** Check for empty description and only add parentheses if needed
                    if ($($comp.Description) -eq " " ) {
                        $Description = ""
                    } else {
                        $Description = "  ($($comp.Description))"
                    }

                    [System.Management.Automation.CompletionResult]::new("$($comp.Name)$Description", "$($comp.Name)$Description", 'ParameterValue', "$($comp.Description)")
                }
             }

            ***REMOVED*** zsh like
            "MenuComplete" {
                ***REMOVED*** insert space after value
                ***REMOVED*** MenuComplete will automatically show the ToolTip of
                ***REMOVED*** the highlighted value at the bottom of the suggestions.
                [System.Management.Automation.CompletionResult]::new($($comp.Name | __%[1]s_escapeStringWithSpecialChars) + $Space, "$($comp.Name)", 'ParameterValue', "$($comp.Description)")
            }

            ***REMOVED*** TabCompleteNext and in case we get something unknown
            Default {
                ***REMOVED*** Like MenuComplete but we don't want to add a space here because
                ***REMOVED*** the user need to press space anyway to get the completion.
                ***REMOVED*** Description will not be shown because that's not possible with TabCompleteNext
                [System.Management.Automation.CompletionResult]::new($($comp.Name | __%[1]s_escapeStringWithSpecialChars), "$($comp.Name)", 'ParameterValue', "$($comp.Description)")
            }
        }

    }
}

Register-ArgumentCompleter -CommandName '%[1]s' -ScriptBlock ${__%[2]sCompleterBlock}
`, name, nameForVar, compCmd,
		ShellCompDirectiveError, ShellCompDirectiveNoSpace, ShellCompDirectiveNoFileComp,
		ShellCompDirectiveFilterFileExt, ShellCompDirectiveFilterDirs, ShellCompDirectiveKeepOrder, activeHelpEnvVar(name)))
}

func (c *Command) genPowerShellCompletion(w io.Writer, includeDesc bool) error {
	buf := new(bytes.Buffer)
	genPowerShellComp(buf, c.Name(), includeDesc)
	_, err := buf.WriteTo(w)
	return err
}

func (c *Command) genPowerShellCompletionFile(filename string, includeDesc bool) error {
	outFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer outFile.Close()

	return c.genPowerShellCompletion(outFile, includeDesc)
}

// GenPowerShellCompletionFile generates powershell completion file without descriptions.
func (c *Command) GenPowerShellCompletionFile(filename string) error {
	return c.genPowerShellCompletionFile(filename, false)
}

// GenPowerShellCompletion generates powershell completion file without descriptions
// and writes it to the passed writer.
func (c *Command) GenPowerShellCompletion(w io.Writer) error {
	return c.genPowerShellCompletion(w, false)
}

// GenPowerShellCompletionFileWithDesc generates powershell completion file with descriptions.
func (c *Command) GenPowerShellCompletionFileWithDesc(filename string) error {
	return c.genPowerShellCompletionFile(filename, true)
}

// GenPowerShellCompletionWithDesc generates powershell completion file with descriptions
// and writes it to the passed writer.
func (c *Command) GenPowerShellCompletionWithDesc(w io.Writer) error {
	return c.genPowerShellCompletion(w, true)
}
