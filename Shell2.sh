#!/bin/bash
# =============================================
# SHELLGUARD ULTRA - STABLE MILITARY GRADE
# =============================================
# By: @isSinc4rely 🕊️  
# Level: Enterprise Stable + Advanced Obfuscation
# =============================================

set -u  # Strict mode

# Global variables
OBFUSCATOR_VERSION="ShellGuard Ultra 3.0"
RANDOM_SEED=$(date +%s)
declare -A VAR_MAPPING
declare -a ERROR_LOG

# =============================================
# ERROR HANDLING & LOGGING
# =============================================

log_error() {
    local msg="$1"
    ERROR_LOG+=("$msg")
    echo "⚠️  ERROR: $msg" >&2
}

log_info() {
    echo "ℹ️  $1"
}

validate_script() {
    local script="$1" context="$2"
    
    if [[ -z "$script" ]]; then
        log_error "Empty script in $context"
        return 1
    fi
    
    # Basic syntax check
    if ! echo "$script" | bash -n 2>/dev/null; then
        log_error "Syntax error in $context"
        return 1
    fi
    
    return 0
}

# =============================================
# STABLE CORE OBFUSCATION FUNCTIONS
# =============================================

generate_obfuscated_name() {
    local prefixes=("_" "__" "v_" "x_" "y_" "z_" "t_" "r_" "a_" "b_")
    local chars=("a" "b" "c" "d" "e" "f" "g" "h" "i" "j" "k" "l" "m" "n" "o" "p" "q" "r" "s" "t" "u" "v" "w" "x" "y" "z")
    
    local prefix="${prefixes[$(( RANDOM % ${#prefixes[@]} ))]}"
    local length=$(( RANDOM % 4 + 3 ))
    local name="$prefix"
    
    for ((i=0; i<length; i++)); do
        name="${name}${chars[$(( RANDOM % ${#chars[@]} ))]}"
    done
    
    # Ensure uniqueness
    while [[ -n "${VAR_MAPPING[$name]}" ]]; do
        name="${name}_$(( RANDOM % 1000 ))"
    done
    
    echo "$name"
}

safe_string_encrypt() {
    local str="$1"
    
    # Method 1: Simple hex encoding (most stable)
    if command -v xxd >/dev/null 2>&1; then
        echo -n "$str" | xxd -p | tr -d '\n'
        return 0
    fi
    
    # Method 2: Manual hex conversion (fallback)
    local hex_result=""
    while IFS= read -r -n1 char; do
        printf "%02X" "'$char"
    done <<< "$str"
    
    echo -n "$hex_result"
}

safe_string_decrypt() {
    local encrypted="$1" method="$2"
    
    case "$method" in
        "hex")
            if command -v xxd >/dev/null 2>&1; then
                echo -n "$encrypted" | xxd -p -r
            else
                # Manual hex decode
                echo -n "$encrypted" | sed 's/\(..\)/\\x\1/g' | xargs -0 printf
            fi
            ;;
        *)
            echo -n "$encrypted"  # Fallback
            ;;
    esac
}

obfuscate_variables_safe() {
    local script="$1"
    local safe_script=""
    
    # Two-pass approach untuk stability
    while IFS= read -r line; do
        # Skip shebang dan comments
        if [[ $line =~ ^#! ]] || [[ $line =~ ^[[:space:]]*# ]]; then
            safe_script+="$line"$'\n'
            continue
        fi
        
        # Safe variable detection dengan boundary matching
        if [[ $line =~ [[:space:]]*([a-zA-Z_][a-zA-Z0-9_]*)= ]]; then
            local var_name="${BASH_REMATCH[1]}"
            
            # Skip built-in and special variables
            if [[ $var_name =~ ^[A-Z_][A-Z0-9_]*$ ]] || 
               [[ " ${!BASH_ALIASES[@]} ${!BASH_COMMANDS[@]} " =~ " $var_name " ]]; then
                safe_script+="$line"$'\n'
                continue
            fi
            
            if [[ -z "${VAR_MAPPING[$var_name]}" ]]; then
                VAR_MAPPING["$var_name"]=$(generate_obfuscated_name)
            fi
            
            # Safe replacement dengan word boundaries
            local new_line=$(echo "$line" | sed "s/\(\b\)$var_name\(\b\)/\1${VAR_MAPPING[$var_name]}\2/g")
            safe_script+="$new_line"$'\n'
        else
            safe_script+="$line"$'\n'
        fi
    done <<< "$script"
    
    echo "$safe_script"
}

encrypt_strings_safe() {
    local script="$1"
    local processed=""
    local string_vars=()
    local var_counter=0
    
    while IFS= read -r line; do
        # Preserve shebang and comments
        if [[ $line =~ ^#! ]] || [[ $line =~ ^[[:space:]]*# ]]; then
            processed+="$line"$'\n'
            continue
        fi
        
        local processed_line="$line"
        
        # Handle double-quoted strings safely
        if [[ $processed_line =~ \"([^\"]*)\" ]]; then
            while [[ $processed_line =~ \"([^\"]*)\" ]]; do
                local full_match="${BASH_REMATCH[0]}"
                local string_content="${BASH_REMATCH[1]}"
                
                if [[ -n "$string_content" && ${#string_content} -gt 0 ]]; then
                    local encrypted=$(safe_string_encrypt "$string_content")
                    local var_name="__str_$((++var_counter))"
                    
                    # Add decryption before the line
                    processed="    $var_name=\\\"$encrypted\\\"\n$processed"
                    # Replace in line
                    processed_line="${processed_line//\"$string_content\"/\"\\$\\$var_name\"}"
                else
                    processed_line="${processed_line//\"$string_content\"/\"\"}"
                fi
            done
        fi
        
        processed+="$processed_line"$'\n'
    done <<< "$script"
    
    # Add decryption function
    local decryption_func="
__DECRYPT_STR() {
    local encrypted=\\\$1
    echo -n \\\"\\\$encrypted\\\" | xxd -p -r 2>/dev/null || echo -n \\\"\\\$encrypted\\\"
}
"
    processed="$decryption_func\n$processed"
    
    echo -e "$processed"
}

# =============================================
# STABLE CONTROL FLOW OBFUSCATION
# =============================================

generate_stable_condition() {
    local conditions=(
        "[ \\$RANDOM -gt 10000 ]"
        "[ \\$(date +%s) -gt $(( RANDOM_SEED + 1000 )) ]"
        "[ -f /proc/version ]"
        "[ -x /bin/bash ]"
        "[ \\$(( \\$(date +%d) + \\$(date +%m) )) -gt 20 ]"
    )
    echo "${conditions[$(( RANDOM % ${#conditions[@]} ))]}"
}

insert_control_flow_safe() {
    local script="$1"
    local processed=""
    local line_num=0
    local block_level=0
    
    while IFS= read -r line; do
        ((line_num++))
        
        # Skip first line (shebang)
        if [[ $line_num -eq 1 && $line =~ ^#! ]]; then
            processed+="$line"$'\n'
            continue
        fi
        
        # Skip empty lines and comments
        if [[ $line =~ ^[[:space:]]*$ ]] || [[ $line =~ ^[[:space:]]*# ]]; then
            processed+="$line"$'\n'
            continue
        fi
        
        # Track block levels
        if [[ $line =~ ^[[:space:]]*(if|while|for|case) ]] || 
           [[ $line =~ [[:space:]](then|do)$ ]] || 
           [[ $line =~ ^[[:space:]]*\{ ]]; then
            ((block_level++))
        fi
        
        if [[ $line =~ ^[[:space:]]*(\}|fi|done|esac) ]] || 
           [[ $line =~ [[:space:]]else[[:space:]] ]]; then
            ((block_level--))
        fi
        
        # Insert control flow obfuscation (every 3-7 lines, outside complex blocks)
        if [[ $(( line_num % $(( RANDOM % 5 + 3 )) )) -eq 0 ]] && 
           [[ $block_level -eq 0 ]] && 
           [[ ! $line =~ ^[[:space:]]*(function|[a-zA-Z_][a-zA-Z0-9_]*\(\)) ]]; then
            
            local condition=$(generate_stable_condition)
            local fake_var=$(generate_obfuscated_name)
            
            processed+="if $condition; then\n"
            processed+="    $fake_var=\\\"obfuscated_block\\\"\n"
            processed+="else\n"
            processed+="    $line\n"
            processed+="fi\n"
        else
            processed+="$line"$'\n'
        fi
    done <<< "$script"
    
    echo "$processed"
}

# =============================================
# STABLE ADVANCED OBFUSCATION
# =============================================

create_function_wrapper() {
    local script="$1"
    local processed=""
    local func_counter=0
    local in_function=0
    local current_func=""
    
    while IFS= read -r line; do
        # Detect function start
        if [[ $line =~ ^[[:space:]]*([a-zA-Z_][a-zA-Z0-9_]*)\(\)[[:space:]]*\{? ]]; then
            in_function=1
            current_func="${BASH_REMATCH[1]}"
            processed+="$line"$'\n'
        # Detect function end
        elif [[ $in_function -eq 1 && $line =~ ^[[:space:]]*\} ]]; then
            in_function=0
            processed+="$line"$'\n'
        # Inside function - obfuscate
        elif [[ $in_function -eq 1 ]]; then
            # Wrap commands in functions
            if [[ $line =~ ^[[:space:]]*([a-zA-Z_][a-zA-Z0-9_]*)=([^#]*) ]]; then
                local var_name="${BASH_REMATCH[1]}"
                local value="${BASH_REMATCH[2]}"
                local wrapper_func="__wrap_${current_func}_$((++func_counter))"
                
                processed+="$wrapper_func() {\n"
                processed+="    $var_name=$value\n"
                processed+="}\n"
                processed+="$wrapper_func\n"
            else
                processed+="$line"$'\n'
            fi
        else
            processed+="$line"$'\n'
        fi
    done <<< "$script"
    
    echo "$processed"
}

split_and_reorder() {
    local script="$1"
    local parts=()
    local current_part=""
    local part_size=0
    local max_part_size=500  # characters per part
    
    # Split script into manageable parts
    while IFS= read -r line; do
        if [[ $(( part_size + ${#line} )) -gt $max_part_size ]]; then
            parts+=("$current_part")
            current_part="$line"$'\n'
            part_size=${#line}
        else
            current_part+="$line"$'\n'
            part_size=$(( part_size + ${#line} ))
        fi
    done <<< "$script"
    
    parts+=("$current_part")
    
    # Reorder parts (keep first 2 parts for header)
    if [[ ${#parts[@]} -gt 3 ]]; then
        for ((i=2; i<${#parts[@]}-1; i++)); do
            local j=$(( RANDOM % (${#parts[@]} - 3) + 2 ))
            local temp="${parts[i]}"
            parts[i]="${parts[j]}"
            parts[j]="$temp"
        done
    fi
    
    # Reconstruct with execution order
    local reconstructed=""
    reconstructed+="${parts[0]}"  # Shebang
    reconstructed+="${parts[1]}"  # Header
    
    # Add execution coordinator
    reconstructed+="__EXEC_PARTS() {\n"
    for ((i=2; i<${#parts[@]}; i++)); do
        local part_var="__part_$i"
        reconstructed+="    $part_var='${parts[i]//\'/\'\\\'\'}'\n"
        reconstructed+="    eval \"\\$$part_var\"\n"
    done
    reconstructed+="}\n"
    reconstructed+="__EXEC_PARTS\n"
    
    echo "$reconstructed"
}

# =============================================
# STABLE ANTI-ANALYSIS PROTECTION
# =============================================

add_anti_analysis_safe() {
    local script="$1"
    
    local protection='
# =============================================
# ANTI-ANALYSIS PROTECTION (SAFE)
# =============================================

__SAFE_CHECK() {
    # Basic environment check
    if [[ -z "$BASH" ]]; then
        return 1
    fi
    
    # Check script integrity (basic)
    if [[ ! -f "$0" ]]; then
        return 1
    fi
    
    # Check if script is being sourced
    if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
        return 1
    fi
    
    return 0
}

# Runtime validation
if ! __SAFE_CHECK; then
    echo "Execution environment invalid" >&2
    exit 1
fi

# Obfuscated code continues below...
'
    
    echo "$protection$script"
}

# =============================================
# MAIN OBFUSCATION ENGINE (STABLE)
# =============================================

obfuscate_shell_stable() {
    local input_file="$1"
    local output_file="$2"
    
    log_info "Starting STABLE obfuscation: $input_file"
    
    # Read and validate input
    if [[ ! -f "$input_file" ]]; then
        log_error "Input file not found: $input_file"
        return 1
    fi
    
    local original_content=$(cat "$input_file")
    if ! validate_script "$original_content" "input"; then
        log_error "Invalid input script"
        return 1
    fi
    
    local obfuscated_content="$original_content"
    
    # Apply obfuscation layers dengan error handling
    log_info "Phase 1: Variable obfuscation"
    obfuscated_content=$(obfuscate_variables_safe "$obfuscated_content")
    if ! validate_script "$obfuscated_content" "variable_obfuscation"; then
        log_error "Variable obfuscation failed"
        return 1
    fi
    
    log_info "Phase 2: String encryption"
    obfuscated_content=$(encrypt_strings_safe "$obfuscated_content")
    if ! validate_script "$obfuscated_content" "string_encryption"; then
        log_error "String encryption failed"
        return 1
    fi
    
    log_info "Phase 3: Control flow obfuscation"
    obfuscated_content=$(insert_control_flow_safe "$obfuscated_content")
    if ! validate_script "$obfuscated_content" "control_flow"; then
        log_error "Control flow obfuscation failed"
        return 1
    fi
    
    log_info "Phase 4: Function wrapping"
    obfuscated_content=$(create_function_wrapper "$obfuscated_content")
    if ! validate_script "$obfuscated_content" "function_wrapping"; then
        log_error "Function wrapping failed"
        return 1
    fi
    
    log_info "Phase 5: Code splitting"
    obfuscated_content=$(split_and_reorder "$obfuscated_content")
    if ! validate_script "$obfuscated_content" "code_splitting"; then
        log_error "Code splitting failed"
        return 1
    fi
    
    log_info "Phase 6: Anti-analysis protection"
    obfuscated_content=$(add_anti_analysis_safe "$obfuscated_content")
    
    # Final validation
    if ! validate_script "$obfuscated_content" "final_output"; then
        log_error "Final validation failed"
        return 1
    fi
    
    # Write output
    echo -e "#!/bin/bash\n# Obfuscated by ShellGuard Ultra (Stable)\n$obfuscated_content" > "$output_file"
    
    if [[ $? -ne 0 ]]; then
        log_error "Failed to write output file: $output_file"
        return 1
    fi
    
    chmod +x "$output_file"
    
    # Final test
    if bash -n "$output_file" 2>/dev/null; then
        log_info "✅ Obfuscation successful: $output_file"
        log_info "📊 Original size: $(wc -c < "$input_file") bytes"
        log_info "📊 Obfuscated size: $(wc -c < "$output_file") bytes"
        log_info "🛡️  Security level: STABLE + ADVANCED"
        return 0
    else
        log_error "Final syntax check failed"
        return 1
    fi
}

# =============================================
# USAGE & MAIN FUNCTION
# =============================================

usage() {
    cat << EOF
ShellGuard Ultra - Stable Advanced Obfuscator
Usage: $0 <input_script.sh> [output_script.sh]

Features:
✅ Stable variable obfuscation
✅ Safe string encryption  
✅ Control flow manipulation
✅ Function wrapping
✅ Code splitting & reordering
✅ Anti-analysis protection
✅ Comprehensive error handling

Examples:
  $0 script.sh                    # Obfuscate to script_obfuscated.sh
  $0 deploy.sh protected.sh       # Custom output name

Safety Features:
• Syntax validation at each step
• Safe variable replacement
• Fallback mechanisms
• Error recovery
EOF
}

main() {
    if [[ $# -eq 0 ]]; then
        usage
        exit 1
    fi
    
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        -v|--version)
            echo "ShellGuard Ultra $OBFUSCATOR_VERSION"
            exit 0
            ;;
        *)
            local input_file="$1"
            local output_file="${2:-${input_file%.*}_obfuscated.sh}"
            
            echo "============================================="
            echo "   SHELLGUARD ULTRA - STABLE ADVANCED"
            echo "============================================="
            
            if obfuscate_shell_stable "$input_file" "$output_file"; then
                echo ""
                echo "🎉 OBFUSCATION COMPLETED SUCCESSFULLY!"
                echo ""
                echo "Next steps:"
                echo "1. Test the script: ./$output_file"
                echo "2. Verify functionality"
                echo "3. Deploy with confidence"
                
                if [[ ${#ERROR_LOG[@]} -gt 0 ]]; then
                    echo ""
                    echo "⚠️  Warnings:"
                    printf '• %s\n' "${ERROR_LOG[@]}"
                fi
            else
                echo ""
                echo "❌ OBFUSCATION FAILED!"
                echo "Errors:"
                printf '• %s\n' "${ERROR_LOG[@]}"
                exit 1
            fi
            ;;
    esac
}

# =============================================
# ENTRY POINT WITH ERROR HANDLING
# =============================================

# Trap errors
trap 'log_error "Script interrupted"; exit 1' INT TERM

# Check dependencies
check_deps() {
    local deps=("bash" "sed" "awk")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            log_error "Missing dependency: $dep"
            exit 1
        fi
    done
}

# Initialize
check_deps
main "$@"