$ErrorActionPreference = 'SilentlyContinue'

<#

    -> Powershell Subnet Calculator
    -> _AUTH_ = 'RWG'
    -> Date: 02/21/2021

 #>

$subnet_masks = @(
                    "255.255.255.255",
                    "255.255.255.254",
                    "255.255.255.252",
                    "255.255.255.248",
                    "255.255.255.240",
                    "255.255.255.224",
                    "255.255.255.192",
                    "255.255.255.128",
                    "255.255.255.0",
                    "255.255.254.0",
                    "255.255.252.0",
                    "255.255.248.0",
                    "255.255.240.0",
                    "255.255.224.0",
                    "225.255.192.0",
                    "255.255.128.0",
                    "255.255.0.0",
                    "255.254.0.0",
                    "255.252.0.0",
                    "255.248.0.0",
                    "255.240.0.0", 
                    "255.224.0.0",  
                    "255.192.0.0",
                    "255.128.0.0",
                    "255.0.0.0",
                    "254.0.0.0",
                    "252.0.0.0",
                    "248.0.0.0",
                    "240.0.0.0",
                    "224.0.0.0",
                    "192.0.0.0",
                    "128.0.0.0",
                    "0.0.0.0"
                )

$cidr = @(
            "/32",
            "/31",
            "/30",
            "/29",
            "/28",
            "/27",
            "/26",
            "/25",
            "/24",
            "/23",
            "/22",
            "/21",
            "/20",
            "/19",
            "/18",
            "/17",
            "/16",
            "/15",
            "/14",
            "/13",
            "/12",
            "/11",
            "/10",
            "/9",
            "/8",
            "/7",
            "/6",
            "/5",
            "/4",
            "/3",
            "/2",
            "/1",
            "/0"
)

function ConvertToBinary($value)
{
    $binary = [System.Convert]::ToString($value,2).PadLeft(8,'0')
    return $binary
}

function ConvertToDecimal($binary)
{
    $decimal = [convert]::ToInt32($binary,2)
    return $decimal
}

function LogicalAndRoutine($addr_binary,$mask_binary)
{
    $network_binary = @()

    for($i = 0; $i -lt $addr_binary.Length; $i++)
    {
        $addr_value = $addr_binary[$i]
        $mask_value = $mask_binary[$i]

        if($addr_value -eq '1' -and $mask_value -eq '1')
        {
            $network_binary += 1
        }
        else
        {
            $network_binary += 0
        }
    }

    return $network_binary
}

function CalculateWildcardMask($mask)
{
    $mask_segments = $mask.split('.')

    $binary_array = @()

    $binary_wcm = @()

    $mask_segments | Foreach-Object {
                                        $element = $_ 

                                        $binary_segment = ConvertToBinary($element)

                                        $binary_array += $binary_segment
                                    }

    $binary_char_array = $binary_array.ToCharArray()

    $binary_char_array | Foreach-Object {
                                            $value = $_ 

                                            if($value -eq '1')
                                            {
                                                $binary_wcm += '0'
                                            }
                                            else
                                            {
                                                $binary_wcm += '1'
                                            }
                                        }
    $decimal_wcm = ConvertToIPFromBinary $binary_wcm

    return $decimal_wcm
}

function CalculateHostsPerSubnet($subnets,$total_hosts)
{
    $hosts_per_subnet = $total_hosts / $subnets 

    $hosts_per_subnet = [math]::floor($hosts_per_subnet)

    return $hosts_per_subnet
}

function CalculateTotalSubnets($mask)
{
    $mask_segments = $mask.Split('.')

    $subnet_bits = 0
    $host_bits   = 0

    $mask_segments | Foreach-Object { 
    
                                        $element = $_ 
                                    
                                        if($element -ne '255')
                                        {
                                            $binary_octet = ConvertToBinary($element)
                                            $binary_array = $binary_octet.ToCharArray()
                                            for($i = 0; $i -lt $binary_array.Length; $i++)
                                            {
                                                if($binary_array[$i] -eq '1')
                                                {
                                                    $subnet_bits += 1
                                                }
                                                else
                                                {
                                                    $host_bits += 1
                                                }
                                            }
                                        }
                                    }
    $total_subnets = [Math]::Pow(2,$subnet_bits)

    return $total_subnets
}

function CalculateTotalHosts($mask)
{
    $mask_segments = $mask.Split('.')

    $subnet_bits = 0
    $host_bits   = 0

    $mask_segments | Foreach-Object { 
    
                                        $element = $_ 
                                    
                                        if($element -ne '255')
                                        {
                                            $binary_octet = ConvertToBinary($element)
                                            $binary_array = $binary_octet.ToCharArray()
                                            for($i = 0; $i -lt $binary_array.Length; $i++)
                                            {
                                                if($binary_array[$i] -eq '1')
                                                {
                                                    $subnet_bits += 1
                                                }
                                                else
                                                {
                                                    $host_bits += 1
                                                }
                                            }
                                        }
                                    }
    $total_hosts = ([Math]::Pow(2,$host_bits))-2 

    return $total_hosts
}

function ConvertToIPFromBinary($binary_addr)
{  
    $temp_arr = @()

    $octet_index   = 0
    $total_octets  = 0
    $temp          = ""

    for($i = 0; $i -lt $binary_addr.Length; $i++)
    {
        $temp += $binary_addr[$i] 
        $octet_index += 1
        if($octet_index -eq 8 -and ($total_octets -le 3))
        {
            $decimal_value = ConvertToDecimal($temp)
            $temp_arr += $decimal_value
            $temp = ""
            $octet_index   = 0
        }
    }

    $standard_addr = [string]::Join('.',$temp_arr) 

    return $standard_addr
}

function IterateAddressRange($first_addr,$last_addr)
{
    $start = $first_addr.Split('.')
    $end   = $last_addr.Split('.')

    $base_address = ""

    $octet_index = 0
    $index_sentinel = $false

    for($i = 0; $i -lt $start.Length; $i++)
    {
        if($start[$i] -ne $end[$i] -and ($index_sentinel -eq $false))
        {
            $octet_index = $i
            $index_sentinel = $true
        }
    }

    if($octet_index -gt 0)
    {
        $base_address = [string]::Join('.',$start,0,$octet_index)
        $base_address += '.'
        $start_index = [convert]::ToInt32($start[$octet_index],10)
        $end_index   = [convert]::ToInt32($end[$octet_index],10)
    }
    else
    {
        $base_address = $start[0] ; Write-Host $start[0]
        $base_address += '.'
        $start_index = [convert]::ToInt32($start[0],10)
        $end_index   = [convert]::ToInt32($end[0],10)
    }
    
    $remaining_octets = (3-$octet_index) 

        switch($remaining_octets)
        {
            0 {  
                while($start_index -le $end_index)
                {
                    $start_index_str = $start_index.ToString()
                    $current_address = -join($base_address,$start_index_str)
                    Write-Host $current_address
                    $start_index += 1
                }
              }
            1 {  
                while($start_index -le $end_index)
                {
                    $start_index_str = $start_index.ToString()
                    $current_address = -join($base_address,$start_index_str)
                    $last_octet = 0
                    while($last_octet -le 255)
                    {
                        $temp_addr = ""
                        $last_octet_as_str = $last_octet.ToString()
                        $temp_addr = -join($current_address,'.',$last_octet_as_str)
                        Write-Host $temp_addr
                        $last_octet += 1
                    }
                    $start_index += 1
                }
              }
            2 {  
                while($start_index -le $end_index)
                {
                    $start_index_str = $start_index.ToString()
                    $current_address = -join($base_address,$start_index_str)
                    $octet_one = 0
                    
                    while($octet_one -le 254)
                    {
                        $octet_one += 1

                        $octet_two = 0

                        while($octet_two -le 255)
                        {
                            $temp_addr = ""

                            $octet_one_as_str = $octet_one.ToString()
                            $octet_two_as_str = $octet_two.ToString()

                            $temp_addr = -join($base_address,$start_index_str,'.',$octet_one_as_str,'.',$octet_two_as_str)

                            Write-Host $temp_addr

                            $octet_two += 1
                        }
                    }
                    $start_index += 1
                 }
              }
            3 {  
                while($start_index -le $end_index)
                {
                    $start_index_str = $start_index.ToString()
                    $current_address = -join($base_address,$start_index_str)
                    $octet_one = 0
                    
                    while($octet_one -le 254)
                    {
                        $octet_one += 1

                        $octet_two = 0

                        while($octet_two -le 254)
                        {
                            $octet_two += 1

                            $octet_three = 0

                            while($octet_three -le 255)
                            {
                                $temp_addr = ""

                                $octet_one_as_str   = $octet_one.ToString()
                                $octet_two_as_str   = $octet_two.ToString()
                                $octet_three_as_str = $octet_three.ToString()

                                $temp_addr = -join($start_index_str,'.',$octet_one_as_str,'.',$octet_two_as_str,'.',$octet_three_as_str)

                                Write-Host $temp_addr

                                $temp_addr | Out-File -Append "test_addrs.txt"

                                $octet_three += 1
                            }
                        }
                    }
                    $start_index += 1
                 }
              }
        }
}

function CalculateSubnetFromCIDR($cidr)
{
    $network_bits = $cidr.TrimStart('/')

    $mask_len = [convert]::ToInt32($network_bits,10)

    $binary_array = @()

    for($i = 0; $i -lt $mask_len; $i++)
    {
        $binary_array += '1'
    }

    $j = $i

    while($j -le 32)
    {
        $binary_array += '0'
        $j++
    }

    $subnet_mask = ConvertToIPFromBinary $binary_array

    return $subnet_mask
}

function CalculateCIDRMask($mask)
{
    $mask_segments = $mask.Split('.')

    $mask_bits = 0

    $mask_char_array = @()

    $mask_segments | Foreach-Object { 
    
                                        $element = $_ 
                                    
                                        $binary = ConvertToBinary $element 
                                    
                                        $mask_binary = $binary.ToCharArray()

                                        $mask_binary | Foreach-Object { 
                                                                            $char_value = $_

                                                                            $mask_char_array += $char_value

                                                                            if($char_value -eq '1')
                                                                            {
                                                                                $mask_bits += 1
                                                                            }
                                                                      }
    
                                    }

    return $mask_bits
}

function CalculateNetworkAddress($address,$mask)
{
    $network = ""
    $network_binary = @()
    $addr_segments = $address.Split('.')
    $mask_segments = $mask.Split('.')

    $mask_bits = 0

    $mask_char_array = @()

    $mask_segments | Foreach-Object { 
    
                                        $element = $_ 
                                    
                                        $binary = ConvertToBinary $element 
                                    
                                        $mask_binary = $binary.ToCharArray()

                                        $mask_binary | Foreach-Object { 
                                                                            $char_value = $_

                                                                            $mask_char_array += $char_value

                                                                            if($char_value -eq '1')
                                                                            {
                                                                                $mask_bits += 1
                                                                            }
                                                                      }
    
                                    }

    $addr_char_array = @()

    $addr_segments | Foreach-Object {
                                        $element = $_

                                        $binary = ConvertToBinary $element

                                        $addr_binary = $binary.ToCharArray()

                                        $addr_binary | Foreach-Object {
                                                                           $char_value = $_

                                                                           $addr_char_array += $char_value
                                                                      }
                                    }

    $network_binary = LogicalAndRoutine $addr_char_array $mask_char_array

    $network_addr = ConvertToIPFromBinary $network_binary

    return $network_addr
}

function CalculateBroadcastAddress($addr,$mask)
{
    $network = ""
    $network_binary = @()
    $addr_segments = $addr.Split('.')
    $mask_segments = $mask.Split('.')

    $mask_bits = 0

    $mask_char_array = @()

    $mask_segments | Foreach-Object { 
    
                                        $element = $_ 
                                    
                                        $binary = ConvertToBinary $element 
                                    
                                        $mask_binary = $binary.ToCharArray()

                                        $mask_binary | Foreach-Object { 
                                                                            $char_value = $_

                                                                            $mask_char_array += $char_value

                                                                            if($char_value -eq '1')
                                                                            {
                                                                                $mask_bits += 1
                                                                            }
                                                                      }
    
                                    }
    $addr_char_array = @()

    $addr_segments | Foreach-Object {
                                        $element = $_

                                        $binary = ConvertToBinary $element

                                        $addr_binary = $binary.ToCharArray()

                                        $addr_binary | Foreach-Object {
                                                                           $char_value = $_

                                                                           $addr_char_array += $char_value
                                                                      }
                                    }

    for($i = $mask_bits; $i -lt $addr_char_array.Length ; $i++)
    {
        $addr_char_array[$i] = '1'
    }

    $broadcast_addr = ConvertToIPFromBinary $addr_char_array

    return $broadcast_addr
}

function CalculateNetworkHosts($addr,$mask)
{
    $addr_segments = $addr.Split('.')
    $mask_segments = $mask.Split('.')

    $binary_array = @()

    $addr_segments | Foreach-Object {
                                        $element = $_ 

                                        $binary = ConvertToBinary($element)

                                        $binary_char_array = $binary.ToCharArray() 
                                        
                                        $binary_char_array | Foreach-Object {
                                                                                $char_value = $_ 

                                                                                $binary_array += $char_value
                                                                            } 
                                    }

    $mask_bits = CalculateCIDRMask $mask

    $broadcast_addr = CalculateBroadcastAddress $addr $mask

    $addr_base = @()

    $host_addr_array = @() 

    for($i = 0; $i -lt $mask_bits; $i++)
    {
        $addr_base += $binary_array[$i]
    }

    $host_addr = ""

    $host_bits_array = @()

    for($i = $mask_bits ; $i -lt $binary_array.Length; $i++)
    {
        $host_bits_array += '0'
    }

    <# Find the first host in the range #>
    $host_bits_array[$host_bits_array.Length-1] = '1'
    $first_host_binary  = $addr_base + $host_bits_array
    $first_host_decimal = ConvertToIPFromBinary $first_host_binary
    
    <# Find the last host in the range #>
    
    $host_bits_array[$host_bits_array.Length-1] = '0'

    for($i = 0 ; $i -lt $host_bits_array.Length-1; $i++)
    {
        $host_bits_array[$i] = '1'
    } 

    $last_host_binary = $addr_base + $host_bits_array
    $last_host_decimal = ConvertToIPFromBinary $last_host_binary 

    $range_array = @($first_host_decimal,$last_host_decimal)

    return $range_array
}

function AppendText($ip_address,$subnet_mask,$cidr_mask)
{
    if($ip_address)
    {
        if($subnet_mask -and (-not $cidr_mask))
        {
            $cidr_mask        = CalculateCIDRMask $subnet_mask

            $network_address  = CalculateNetworkAddress $ip_address $subnet_mask

            $total_hosts      = CalculateTotalHosts $subnet_mask

            $total_subnets    = CalculateTotalSubnets $subnet_mask

            $hosts_per_subnet = CalculateHostsPerSubnet $total_subnets $total_hosts

            $host_range       = CalculateNetworkHosts $ip_address $subnet_mask

            $first_host = $host_range[0]
            $last_host  = $host_range[1]

            $wildcard_mask = CalculateWildcardMask $subnet_mask
        }
        elseif($cidr_mask -and (-not $subnet_mask))
        {
            $subnet_from_cidr    = CalculateSubnetFromCIDR $cidr_mask

            $subnet_mask         = $subnet_from_cidr

            $network_address     = CalculateNetworkAddress $ip_address $subnet_mask

            $total_hosts         = CalculateTotalHosts $subnet_mask

            $total_subnets       = CalculateTotalSubnets $subnet_mask

            $hosts_per_subnet    = CalculateHostsPerSubnet $total_subnets $total_hosts

            $host_range          = CalculateNetworkHosts $ip_address $subnet_mask

            $first_host = $host_range[0]
            $last_host  = $host_range[1]

            $wildcard_mask = CalculateWildcardMask $subnet_mask
        }
        elseif($cidr_mask -and $subnet_mask)
        {
            $subnet_mask      = $subnet_dropdown_listing.Text

            $network_address  = CalculateNetworkAddress $ip_address $subnet_mask

            $total_hosts      = CalculateTotalHosts $subnet_mask

            $total_subnets    = CalculateTotalSubnets $subnet_mask

            $hosts_per_subnet = CalculateHostsPerSubnet $total_subnets $total_hosts

            $host_range       = CalculateNetworkHosts $ip_address $subnet_mask

            $first_host = $host_range[0]
            $last_host  = $host_range[1]

            $wildcard_mask = CalculateWildcardMask $subnet_mask
        }
        else
        {
            return
        }
        $output_box.AppendText("Supplied Address: $ip_address `r`n")
        $output_box.AppendText("Subnet mask: $subnet_mask `r`n")
        $output_box.AppendText("Wildcard Mask: $wildcard_mask `r`n")
        $output_box.AppendText("Subnet CIDR Notation: $cidr_mask `r`n")
        $output_box.AppendText("Network Address: $network_address `r`n")
        $output_box.AppendText("Total Hosts: $total_hosts `r`n")
        $output_box.AppendText("Total Subnets: $total_subnets `r`n")
        $output_box.AppendText("Hosts per Subnet: $hosts_per_subnet `r`n")
        $output_box.AppendText("First Host: $first_host `r`n")
        $output_box.AppendText("Last Host: $last_host `r`n")
        $output_box.AppendText("`r`n")
        $output_box.Refresh()
        $output_box.ScrollToCaret()
    }
    else
    {
        $output_box.AppendText("No network data was supplied... `r`n")
        $output_box.AppendText()
        $output_box.Refresh()
        $output_box.ScrollToCaret()
        return
    }
}

function main()
{
    Add-Type -AssemblyName System.Windows.Forms

    $form               = New-Object System.Windows.Forms.Form
    $form.Text          = 'Subnet Calculator'
    $form.Width         = 500
    $form.Height        = 500
    $form.AutoSize      = $true
    $form.StartPosition = 'CenterScreen'

    $addr_input_label          = New-Object System.Windows.Forms.Label 
    $addr_input_label.Location = New-Object System.Drawing.Point(10,20) 
    $addr_input_label.Size     = New-Object System.Drawing.Size(280,20) 
    $addr_input_label.Text     = "Enter the IP Address:"
    $addr_input_label.AutoSize = $true
    $form.Controls.Add($addr_input_label)

    $addr_input_field          = New-Object System.Windows.Forms.TextBox 
    $addr_input_field.Location = New-Object System.Drawing.Point(10,40) 
    $addr_input_field.Size     = New-Object System.Drawing.Size(260,200)
    $form.Controls.Add($addr_input_field)

    $subnet_dropdown_label = New-Object System.Windows.Forms.Label 
    $subnet_dropdown_label.Location = New-Object System.Drawing.Point(10,80) 
    $subnet_dropdown_label.Size = New-Object System.Drawing.Size(280,60)
    $subnet_dropdown_label.Text = "Pick the subnet mask:"
    $subnet_dropdown_label.AutoSize = $true 
    $form.Controls.Add($subnet_dropdown_label) 

    $subnet_dropdown_listing = New-Object System.Windows.Forms.ComboBox
    $subnet_dropdown_listing.Location = New-Object System.Drawing.Point(10,100) 
    $subnet_dropdown_listing.Size     = New-Object System.Drawing.Size(260,200)
    $subnet_dropdown_listing.AutoSize = $true 

    $subnet_masks | Foreach-Object {
                                        $mask = $_
                                        $subnet_dropdown_listing.Items.Add($mask) | Out-Null
                                   }

    $form.Controls.Add($subnet_dropdown_listing)

    $cidr_dropdown_label = New-Object System.Windows.Forms.Label 
    $cidr_dropdown_label.Location = New-Object System.Drawing.Point(300,80) 
    $cidr_dropdown_label.Size = New-Object System.Drawing.Size(60,60)
    $cidr_dropdown_label.Text = "Pick the subnet mask (CIDR):"
    $cidr_dropdown_label.AutoSize = $true 
    $form.Controls.Add($cidr_dropdown_label) 

    $cidr_dropdown_listing          = New-Object System.Windows.Forms.ComboBox
    $cidr_dropdown_listing.Location = New-Object System.Drawing.Point(300,100) 
    $cidr_dropdown_listing.Size     = New-Object System.Drawing.Size(150,100)
    $cidr_dropdown_listing.AutoSize = $true 

    $cidr | Foreach-Object {
                                $mask = $_
                                $cidr_dropdown_listing.Items.Add($mask) | Out-Null
                           }

    $form.Controls.Add($cidr_dropdown_listing)

    $output_dropdown_label = New-Object System.Windows.Forms.Label 
    $output_dropdown_label.Location = New-Object System.Drawing.Point(10,180) 
    $output_dropdown_label.Size = New-Object System.Drawing.Size(60,60)
    $output_dropdown_label.Text = "Results"
    $output_dropdown_label.AutoSize = $true 
    $form.Controls.Add($output_dropdown_label) 

    $output_box = New-Object System.Windows.Forms.TextBox 
    $output_box.Location = New-Object System.Drawing.Point(10,200) 
    $output_box.Size = New-Object System.Drawing.Size(460,250)
    $output_box.MultiLine = $true
    $output_box.ScrollBars = 'Vertical'
    $form.Controls.Add($output_box)

    $calculate_button = New-Object System.Windows.Forms.Button
    $calculate_button.Location = New-Object System.Drawing.Point(150,140)
    $calculate_button.Size = New-Object System.Drawing.Size(120,30)
    $calculate_button.Text = "Calculate"
    #$calculate_button.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $calculate_button.Add_Click({AppendText $addr_input_field.Text $subnet_dropdown_listing.Text $cidr_dropdown_listing.Text })
    $form.AcceptButton = $calculate_button
    $form.Controls.Add($calculate_button)

    $cancel_button = New-Object System.Windows.Forms.Button
    $cancel_button.Location = New-Object System.Drawing.Point(10,140)
    $cancel_button.Size = New-Object System.Drawing.Size(120,30)
    $cancel_button.Text = "Cancel"
    $cancel_button.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.AcceptButton = $cancel_button
    $form.Controls.Add($cancel_button)

    $intake = $form.ShowDialog()
    
}

main
