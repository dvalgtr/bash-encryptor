#!/bin/bash
# =============================================
# SHELLGUARD PRO - ADVANCED SHELL OBFUSCATOR
# =============================================
# By: @isSinc4rely 🕊️
# Level: Military Grade
# =============================================

# Global variables
OBFUSCATOR_VERSION="ShellGuard Pro 2.0"
RANDOM_SEED=$(date +%s)
declare -A VAR_MAPPING

# =============================================
# CORE OBFUSCATION FUNCTIONS
# =============================================

# Advanced string encryption dengan multiple methods
string_encrypt() {
    local str="$1"
    local method=$(( RANDOM % 4 ))
    
    case $method in
        0)  # HEX + REVERSE
            echo -n "$str" | xxd -p | rev
            ;;
        1)  # BASE64 + ROT13
            echo -n "$str" | base64 | tr 'A-Za-z' 'N-ZA-Mn-za-m'
            ;;
        2)  # CUSTOM XOR ENCRYPTION
            local key=$(( RANDOM % 256 ))
            echo -n "$str" | while IFS= read -r -n1 char; do
                printf "%02X" "$(( ( $(printf "%d" "'$char") ^ key ) ))"
            done
            ;;
        3)  # MULTI-LAYER ENCODING
            echo -n "$str" | base64 | xxd -p | rev
            ;;
    esac
}

string_decrypt_func() {
    local method="$1"
    local var_name="$2"
    local encoded_str="$3"
    
    case $method in
        0)  # HEX + REVERSE DECODE
            echo "    $var_name=\\\$(echo \"$encoded_str\" | rev | xxd -p -r)"
            ;;
        1)  # BASE64 + ROT13 DECODE  
            echo "    $var_name=\\\$(echo \"$encoded_str\" | tr 'A-Za-z' 'N-ZA-Mn-za-m' | base64 -d)"
            ;;
        2)  # XOR DECODE
            local key=$(( RANDOM % 256 ))
            echo "    $var_name=\\\$(echo \"$encoded_str\" | sed 's/../\\\\\\\\x&/g' | printf \"%b\" | while IFS= read -r -n1 char; do printf \"\\\\\\\\x%02X\" \"\\\$(( ( \\\$(printf \"%d\" \"'\\\\\\$char\") ^ $key ) ))\"; done | printf \"%b\")"
            ;;
        3)  # MULTI-LAYER DECODE
            echo "    $var_name=\\\$(echo \"$encoded_str\" | rev | xxd -p -r | base64 -d)"
            ;;
    esac
}

# Generate random variable names
generate_obfuscated_name() {
    local prefix=("_" "__" "___" "____" "var_" "tmp_" "data_" "x_" "y_" "z_")
    local chars=("a" "b" "c" "d" "e" "f" "g" "h" "i" "j" "k" "l" "m" "n" "o" "p" "q" "r" "s" "t" "u" "v" "w" "x" "y" "z")
    
    local name="${prefix[$(( RANDOM % ${#prefix[@]} ))]}"
    local length=$(( RANDOM % 6 + 2 ))
    
    for ((i=0; i<length; i++)); do
        name="${name}${chars[$(( RANDOM % ${#chars[@]} ))]}"
    done
    
    echo "$name"
}

# Obfuscate semua variables dalam script
obfuscate_variables() {
    local script="$1"
    
    # Extract semua variables
    while IFS= read -r line; do
        if [[ $line =~ ([a-zA-Z_][a-zA-Z0-9_]*)= ]]; then
            local var_name="${BASH_REMATCH[1]}"
            if [[ ! ${VAR_MAPPING[$var_name]} ]] && [[ ${#var_name} -gt 1 ]]; then
                VAR_MAPPING["$var_name"]=$(generate_obfuscated_name)
            fi
        fi
    done <<< "$script"
    
    # Replace semua variables
    for var_name in "${!VAR_MAPPING[@]}"; do
        script=$(echo "$script" | sed "s/\\b$var_name\\b/${VAR_MAPPING[$var_name]}/g")
    done
    
    echo "$script"
}

# Generate fake conditions untuk control flow obfuscation
generate_fake_condition() {
    local conditions=(
        "[ \\$(( RANDOM % 1000 )) -eq $(( RANDOM % 1000 )) ]"
        "[ \\$(( $RANDOM_SEED % 2 )) -eq 1 ]"
        "[ -n \"\" ]"
        "[ ! -z \"\\$NONEXISTENT_VAR\" ]"
        "[ \\$(( \$(date +%s) % 2 )) -eq 0 ]"
        "[ \\$(( \$(date +%d) % 3 )) -eq 1 ]"
    )
    echo "${conditions[$(( RANDOM % ${#conditions[@]} ))]}"
}

# Insert fake conditions ke dalam script
insert_fake_conditions() {
    local script="$1"
    local obfuscated=""
    local line_count=0
    
    while IFS= read -r line; do
        ((line_count++))
        
        # Skip shebang dan empty lines
        if [[ $line_count -eq 1 && $line =~ ^#! ]]; then
            obfuscated="$line"
            continue
        fi
        
        # Skip comment lines
        if [[ $line =~ ^[[:space:]]*# ]]; then
            obfuscated+="\n$line"
            continue
        fi
        
        # Insert fake conditions setiap 2-4 lines
        if [[ $(( line_count % $(( RANDOM % 3 + 2 )) )) -eq 0 ]] && [[ ! $line =~ ^[[:space:]]*$ ]]; then
            local condition=$(generate_fake_condition)
            obfuscated+="\nif $condition; then\n    : # fake branch\n    : # more fake\nelse\n    $line\nfi"
        else
            obfuscated+="\n$line"
        fi
    done <<< "$script"
    
    echo -e "$obfuscated"
}

# Encrypt strings dalam script
encrypt_strings() {
    local script="$1"
    local processed_script=""
    local line_count=0
    
    while IFS= read -r line; do
        ((line_count++))
        local processed_line="$line"
        
        # Skip shebang di line 1
        if [[ $line_count -eq 1 && $line =~ ^#! ]]; then
            processed_script="$line"
            continue
        fi
        
        # Process quoted strings
        if [[ $processed_line =~ (\"[^\"]*\")|(\'[^\']*\') ]]; then
            while [[ $processed_line =~ ([\\\"\\'])([^\\\"\\']*)([\\\"\\']) ]]; do
                local full_match="${BASH_REMATCH[0]}"
                local string_content="${BASH_REMATCH[0]}"
                local quote_char="${BASH_REMATCH[1]}"
                local string_value="${BASH_REMATCH[2]}"
                
                if [[ -n "$string_value" && ${#string_value} -gt 1 ]]; then
                    local encrypted=$(string_encrypt "$string_value")
                    local new_var=$(generate_obfuscated_name)
                    local decryption_call=$(string_decrypt_func $? "$new_var" "$encrypted")
                    
                    # Add decryption code before the line
                    processed_script+="\n$decryption_call"
                    # Replace string with variable
                    processed_line="${processed_line//$string_content/\\$$new_var}"
                fi
                
                # Remove the processed match
                processed_line="${processed_line//$full_match/}"
            done
        fi
        
        processed_script+="\n$processed_line"
    done <<< "$script"
    
    echo -e "$processed_script"
}

# Shuffle code blocks
shuffle_code_blocks() {
    local script="$1"
    declare -a blocks
    local current_block=""
    local in_function=0
    
    while IFS= read -r line; do
        # Detect function start
        if [[ $line =~ ^[a-zA-Z_][a-zA-Z0-9_]*\\(\\) ]]; then
            if [[ -n $current_block ]]; then
                blocks+=("$current_block")
            fi
            current_block="$line"
            in_function=1
        elif [[ $in_function -eq 1 && $line =~ ^[[:space:]]*$ ]]; then
            current_block+="\n$line"
            blocks+=("$current_block")
            current_block=""
            in_function=0
        elif [[ $in_function -eq 0 && $line =~ ^[[:space:]]*$ && -n $current_block ]]; then
            blocks+=("$current_block")
            current_block=""
        else
            current_block+="\n$line"
        fi
    done <<< "$script"
    
    if [[ -n $current_block ]]; then
        blocks+=("$current_block")
    fi
    
    # Shuffle blocks (keep first 2 blocks for shebang and headers)
    if [[ ${#blocks[@]} -gt 3 ]]; then
        for ((i=2; i<${#blocks[@]}-1; i++)); do
            local random_index=$(( RANDOM % (${#blocks[@]} - 3) + 2 ))
            local temp="${blocks[i]}"
            blocks[i]="${blocks[random_index]}"
            blocks[random_index]="$temp"
        done
    fi
    
    # Reconstruct script
    local shuffled_script=""
    for block in "${blocks[@]}"; do
        shuffled_script+="$block\n"
    done
    
    echo -e "$shuffled_script"
}

# Generate anti-debugging protection
generate_anti_debug() {
    local anti_debug_code=$(cat << 'ANTI_DEBUG'
# =============================================
# ANTI-DEBUGGING & ANTI-TAMPERING PROTECTION
# =============================================

# Check if being traced
if [[ -n "$BASH_XTRACEFD" ]]; then
    echo "Debugging detected! Exiting..." >&2
    exit 1
fi

# Check parent process for debuggers
parent_cmd=$(ps -o comm= $PPID 2>/dev/null)
if [[ "$parent_cmd" =~ (gdb|strace|ltrace|radare2) ]]; then
    echo "Debugger detected! Exiting..." >&2
    exit 1
fi

# Checksum self-validation
SELF_CHECKSUM=$(sha256sum "$0" 2>/dev/null | cut -d' ' -f1)
EXPECTED_CHECKSUM="%SELF_CHECKSUM%"
if [[ "$SELF_CHECKSUM" != "$EXPECTED_CHECKSUM" ]]; then
    echo "Script modified! Exiting..." >&2
    exit 1
fi

# Execution time validation
START_TIME=$(date +%s)
ANTI_DEBUG
)
    
    local actual_checksum=$(sha256sum "$input_file" | cut -d' ' -f1)
    anti_debug_code="${anti_debug_code/\%SELF_CHECKSUM\%/$actual_checksum}"
    
    echo "$anti_debug_code"
}

# =============================================
# ADVANCED OBFUSCATION FUNCTIONS
# =============================================

# Self-modifying code dengan runtime decryption
generate_self_modifying_code() {
    local script="$1"
    
    local stub=$(cat << 'SELF_MODIFYING'
#!/bin/bash
# =============================================
# SELF-MODIFYING SHELL SCRIPT - PHASE 1 LOADER
# =============================================

__PHASE1_DECRYPT() {
    local ENCRYPTED_DATA="$1"
    local DECRYPT_KEY=$(date +%Y%m%d%H)
    
    # Phase 1: Decrypt Phase 2 code
    local PHASE2_CODE=$(echo "$ENCRYPTED_DATA" | openssl enc -d -aes-256-cbc -k "$DECRYPT_KEY" -base64 2>/dev/null)
    
    if [[ -n "$PHASE2_CODE" ]]; then
        # Execute decrypted Phase 2
        eval "$PHASE2_CODE"
    else
        echo "Invalid execution environment" >&2
        exit 1
    fi
}

# Encrypted Phase 2 payload
ENCRYPTED_PAYLOAD="%ENCRYPTED_PAYLOAD%"

# Anti-tampering: Validate before execution
if [[ $(stat -c %Y "$0" 2>/dev/null || stat -f %m "$0" 2>/dev/null) -gt $(( $(date +%s) - 300 )) ]]; then
    echo "Script recently modified!" >&2
    exit 1
fi

__PHASE1_DECRYPT "$ENCRYPTED_PAYLOAD"
exit 0

# Encrypted data section
SELF_MODIFYING
)

    local key=$(date +%Y%m%d%H)
    local encrypted_payload=$(echo "$script" | openssl enc -e -aes-256-cbc -k "$key" -base64 2>/dev/null || echo "$script")
    
    stub="${stub/\%ENCRYPTED_PAYLOAD\%/$encrypted_payload}"
    echo "$stub"
}

# Polymorphic code generation
generate_polymorphic_variants() {
    local script="$1"
    local variant=$(( RANDOM % 2 ))
    
    case $variant in
        0)
            # VARIANT A: Function-based obfuscation
            script=$(echo "$script" | sed 's/\([a-zA-Z_][a-zA-Z0-9_]*\)=\([^#]*\)$/__SET_VAR "\1" "\2"/g')
            script="__SET_VAR() { eval \"\$1=\\\$2\"; }\n$script"
            ;;
        1)
            # VARIANT B: Encoded command blocks
            script=$(echo "$script" | while IFS= read -r line; do
                if [[ ! $line =~ ^[[:space:]]*# ]] && [[ -n $line ]] && [[ ! $line =~ ^[[:space:]]*$ ]]; then
                    local encoded=$(echo "$line" | base64 -w 0)
                    echo "eval \"\$(echo '$encoded' | base64 -d)\""
                else
                    echo "$line"
                fi
            done)
            ;;
    esac
    
    echo -e "$script"
}

# Advanced anti-disassembly techniques
generate_anti_disassembly() {
    local script="$1"
    
    local anti_analysis=$(cat << 'ANTI_ANALYSIS'
# =============================================
# ANTI-ANALYSIS & ANTI-DISASSEMBLY TECHNIQUES
# =============================================

# Environment sensitive execution
__CHECK_ENV() {
    local REQUIRED_VARS=("SHELL" "USER" "HOME" "PATH")
    for var in "${REQUIRED_VARS[@]}"; do
        if [[ -z "${!var}" ]]; then
            return 1
        fi
    done
    return 0
}

# Time-based validation
__TIME_VALIDATE() {
    local START_TIME=$(date +%s)
    local waste_time=$(( (RANDOM % 500) + 100 ))
    for ((i=0; i<waste_time; i++)); do
        : $(( RANDOM * RANDOM / (RANDOM + 1) ))
    done
    local END_TIME=$(date +%s)
    local ELAPSED=$((END_TIME - START_TIME))
    [[ $ELAPSED -lt 5 ]]
}

# Execute anti-analysis checks
if ! __CHECK_ENV || ! __TIME_VALIDATE; then
    echo "Execution environment invalid" >&2
    exit 1
fi

ANTI_ANALYSIS
)

    echo "$anti_analysis\n$script"
}

# Metamorphic engine - code morphing
generate_metamorphic_code() {
    local script="$1"
    
    local metamorphic=$(cat << 'METAMORPHIC'
#!/bin/bash
# =============================================
# METAMORPHIC SHELL SCRIPT - CODE MORPHING ENGINE
# =============================================

__MORPH_ENGINE() {
    local CODE_BLOCK="$1"
    local MORPH_ID=$(( RANDOM % 1000 ))
    
    case $MORPH_ID in
        [0-499])
            # MORPH TYPE 1: Command substitution
            CODE_BLOCK=$(echo "$CODE_BLOCK" | sed 's/\([a-zA-Z_][a-zA-Z0-9_]*\)=/local \1=/g')
            ;;
        *)
            # MORPH TYPE 2: Encoded blocks
            local ENCODED=$(echo "$CODE_BLOCK" | base64 -w 0)
            CODE_BLOCK="eval \"\$(echo '$ENCODED' | base64 -d)\""
            ;;
    esac
    
    echo "$CODE_BLOCK"
}

# Split script into blocks and morph each one
declare -a CODE_BLOCKS
METAMORPHIC
)

    local block_num=0
    while IFS= read -r line; do
        if [[ -n "$line" && ! "$line" =~ ^[[:space:]]*# ]]; then
            metamorphic+="CODE_BLOCKS[$block_num]='$line'\n"
            ((block_num++))
        fi
    done <<< "$script"
    
    metamorphic+="\n# Execute morphed code blocks\n"
    metamorphic+="for ((i=0; i<$block_num; i++)); do\n"
    metamorphic+="    MORPHED_CODE=\$(__MORPH_ENGINE \"\${CODE_BLOCKS[i]}\")\n"
    metamorphic+="    eval \"\$MORPHED_CODE\"\n"
    metamorphic+="done\n"
    
    echo -e "$metamorphic"
}

# Add runtime integrity checks
add_runtime_integrity() {
    local script="$1"
    
    local integrity=$(cat << 'RUNTIME_INTEGRITY'
# RUNTIME INTEGRITY MONITOR
__MONITOR_SCRIPT() {
    local EXPECTED_HASH="%SCRIPT_HASH%"
    local CURRENT_HASH=$(sha256sum "$0" 2>/dev/null | cut -d' ' -f1)
    
    if [[ "$EXPECTED_HASH" != "$CURRENT_HASH" ]]; then
        echo "Script integrity compromised!" >&2
        exit 1
    fi
}

# Continuous monitoring (simplified)
__MONITOR_SCRIPT
RUNTIME_INTEGRITY
)

    local script_hash=$(echo "$script" | sha256sum | cut -d' ' -f1)
    integrity="${integrity/\%SCRIPT_HASH\%/$script_hash}"
    
    echo "$integrity\n$script"
}

# =============================================
# MAIN OBFUSCATION ENGINES
# =============================================

# Basic obfuscation engine
obfuscate_shell_script() {
    local input_file="$1"
    local output_file="$2"
    
    echo "[+] Reading source script: $input_file"
    local script_content=$(cat "$input_file")
    
    echo "[+] Generating anti-debugging protection..."
    local anti_debug=$(generate_anti_debug)
    
    echo "[+] Obfuscating variable names..."
    local obfuscated_content=$(obfuscate_variables "$script_content")
    
    echo "[+] Encrypting string literals..."
    obfuscated_content=$(encrypt_strings "$obfuscated_content")
    
    echo "[+] Inserting control flow obfuscation..."
    obfuscated_content=$(insert_fake_conditions "$obfuscated_content")
    
    echo "[+] Shuffling code blocks..."
    obfuscated_content=$(shuffle_code_blocks "$obfuscated_content")
    
    echo "[+] Generating final obfuscated script..."
    
    local final_script="#!/bin/bash\n"
    final_script+="# =============================================\n"
    final_script+="# OBFUSCATED BY SHELLGUARD $OBFUSCATOR_VERSION\n"
    final_script+="# =============================================\n\n"
    final_script+="$anti_debug\n\n"
    final_script+="$obfuscated_content"
    
    echo -e "$final_script" > "$output_file"
    chmod +x "$output_file"
    
    echo "[+] Obfuscation complete: $output_file"
    echo "[+] Original size: $(wc -c < "$input_file") bytes"
    echo "[+] Obfuscated size: $(wc -c < "$output_file") bytes"
    echo "[+] Security level: BASIC"
}

# Advanced obfuscation engine (Military Grade)
obfuscate_shell_script_advanced() {
    local input_file="$1"
    local output_file="$2"
    
    echo "[+] READING SOURCE: $input_file"
    local script_content=$(cat "$input_file")
    
    echo "[+] APPLYING METAMORPHIC ENGINE..."
    script_content=$(generate_metamorphic_code "$script_content")
    
    echo "[+] GENERATING ANTI-DISASSEMBLY PROTECTION..."
    script_content=$(generate_anti_disassembly "$script_content")
    
    echo "[+] APPLYING POLYMORPHIC VARIANT..."
    script_content=$(generate_polymorphic_variants "$script_content")
    
    echo "[+] GENERATING SELF-MODIFYING CODE..."
    script_content=$(generate_self_modifying_code "$script_content")
    
    echo "[+] ADDING RUNTIME INTEGRITY CHECKS..."
    script_content=$(add_runtime_integrity "$script_content")
    
    echo "[+] FINALIZING OBFUSCATED SCRIPT..."
    echo -e "$script_content" > "$output_file"
    chmod +x "$output_file"
    
    echo "[+] ADVANCED OBFUSCATION COMPLETE: $output_file"
    echo "[+] SECURITY LEVEL: MILITARY GRADE"
    echo "[+] WARNING: Highly resistant to decompilation"
}

# =============================================
# USAGE & MAIN FUNCTION
# =============================================

usage() {
    echo "ShellGuard Pro - Advanced Shell Script Obfuscator"
    echo "Usage: $0 [OPTIONS] <input_script.sh> [output_script.sh]"
    echo ""
    echo "Options:"
    echo "  -a, --advanced    Use advanced military-grade obfuscation"
    echo "  -v, --version     Show version information" 
    echo "  -h, --help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 script.sh                          # Basic obfuscation"
    echo "  $0 -a script.sh                       # Advanced obfuscation"
    echo "  $0 script.sh protected.sh             # Custom output name"
    echo "  $0 -a script.sh military.sh           # Advanced + custom output"
}

# Main execution function
main() {
    local advanced_mode=0
    local input_file=""
    local output_file=""
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -a|--advanced)
                advanced_mode=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            -v|--version)
                echo "ShellGuard Pro $OBFUSCATOR_VERSION"
                exit 0
                ;;
            *)
                if [[ -z "$input_file" ]]; then
                    input_file="$1"
                elif [[ -z "$output_file" ]]; then
                    output_file="$1"
                fi
                shift
                ;;
        esac
    done
    
    if [[ -z "$input_file" ]]; then
        usage
        exit 1
    fi
    
    if [[ ! -f "$input_file" ]]; then
        echo "Error: Input file '$input_file' not found!" >&2
        exit 1
    fi
    
    if [[ -z "$output_file" ]]; then
        output_file="${input_file%.*}_obfuscated.sh"
    fi
    
    echo "============================================="
    echo "    SHELLGUARD PRO OBFUSCATOR"
    echo "============================================="
    
    if [[ $advanced_mode -eq 1 ]]; then
        obfuscate_shell_script_advanced "$input_file" "$output_file"
    else
        obfuscate_shell_script "$input_file" "$output_file"
    fi
    
    echo ""
    echo "Next steps:"
    echo "1. chmod +x $output_file"
    echo "2. ./$output_file"
    echo "3. Test the obfuscated script"
}

# =============================================
# INITIALIZATION & EXECUTION
# =============================================

# Check if openssl is available (for advanced features)
check_dependencies() {
    if ! command -v openssl &> /dev/null; then
        echo "Warning: openssl not found. Advanced features will be limited."
        echo "Install with: sudo apt-get install openssl"
    fi
    
    if ! command -v xxd &> /dev/null; then
        echo "Warning: xxd not found. Some obfuscation features may not work."
        echo "Install with: sudo apt-get install xxd"
    fi
}

# Initialize and run
check_dependencies
main "$@"