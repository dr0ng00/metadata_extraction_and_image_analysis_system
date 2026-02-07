#!/bin/bash
# MetaForensicAI Dependency Installation Script
# Author: MetaForensicAI Research Team
# Version: 1.0.0

set -e  # Exit on error

echo "================================================"
echo "   MetaForensicAI - Dependency Installation"
echo "================================================"
echo ""
echo "System Requirements:"
echo "  • Python 3.8 or higher"
echo "  • 4GB RAM minimum"
echo "  • 2GB free disk space"
echo "  • Internet connection"
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect operating system
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/debian_version ]; then
            echo "debian"
        elif [ -f /etc/redhat-release ]; then
            echo "redhat"
        elif [ -f /etc/arch-release ]; then
            echo "arch"
        else
            echo "linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        echo "windows"
    else
        echo "unknown"
    fi
}

# Check Python version
print_status "Checking Python version..."
if command_exists python3; then
    PYTHON_CMD="python3"
elif command_exists python; then
    PYTHON_CMD="python"
else
    print_error "Python not found. Please install Python 3.8 or higher."
    exit 1
fi

PYTHON_VERSION=$($PYTHON_CMD -c "import sys; print('.'.join(map(str, sys.version_info[:3])))")
PYTHON_MAJOR=$($PYTHON_CMD -c "import sys; print(sys.version_info.major)")
PYTHON_MINOR=$($PYTHON_CMD -c "import sys; print(sys.version_info.minor)")

if [ $PYTHON_MAJOR -lt 3 ] || [ $PYTHON_MAJOR -eq 3 -a $PYTHON_MINOR -lt 8 ]; then
    print_error "Python 3.8 or higher required. Found version $PYTHON_VERSION"
    exit 1
fi

print_success "Python $PYTHON_VERSION found"

# Detect OS
OS_TYPE=$(detect_os)
print_status "Detected operating system: $OS_TYPE"

# Create virtual environment
print_status "Creating virtual environment..."
if [ ! -d "venv" ]; then
    $PYTHON_CMD -m venv venv
    print_success "Virtual environment created"
else
    print_warning "Virtual environment already exists"
fi

# Activate virtual environment
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
    print_status "Virtual environment activated"
elif [ -f "venv/Scripts/activate" ]; then
    source venv/Scripts/activate
    print_status "Virtual environment activated"
else
    print_error "Could not activate virtual environment"
    exit 1
fi

# Upgrade pip
print_status "Upgrading pip..."
pip install --upgrade pip
print_success "pip upgraded"

# Install Python dependencies
print_status "Installing Python dependencies from requirements.txt..."
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
    print_success "Python dependencies installed"
else
    print_error "requirements.txt not found"
    exit 1
fi

# Install ExifTool based on OS
print_status "Installing ExifTool..."
case $OS_TYPE in
    "debian"|"ubuntu")
        if command_exists apt-get; then
            sudo apt-get update
            sudo apt-get install -y libimage-exiftool-perl
            print_success "ExifTool installed via apt"
        else
            print_error "apt-get not found"
        fi
        ;;
    "redhat"|"centos"|"fedora")
        if command_exists yum; then
            sudo yum install -y perl-Image-ExifTool
            print_success "ExifTool installed via yum"
        elif command_exists dnf; then
            sudo dnf install -y perl-Image-ExifTool
            print_success "ExifTool installed via dnf"
        else
            print_error "Package manager not found"
        fi
        ;;
    "arch")
        if command_exists pacman; then
            sudo pacman -S --noconfirm perl-image-exiftool
            print_success "ExifTool installed via pacman"
        else
            print_error "pacman not found"
        fi
        ;;
    "macos")
        if command_exists brew; then
            brew install exiftool
            print_success "ExifTool installed via Homebrew"
        else
            print_error "Homebrew not found. Please install ExifTool manually."
            echo "Visit: https://exiftool.org/install.html#MacOS"
        fi
        ;;
    "windows")
        print_warning "Windows detected. Please install ExifTool manually."
        echo "Download from: https://exiftool.org/exiftool-12.72.zip"
        echo "Extract and add to PATH"
        ;;
    *)
        print_warning "Unknown OS. Please install ExifTool manually."
        echo "Visit: https://exiftool.org/install.html"
        ;;
esac

# Install additional system dependencies
print_status "Installing additional system dependencies..."
case $OS_TYPE in
    "debian"|"ubuntu")
        sudo apt-get install -y \
            libgl1-mesa-glx \
            libglib2.0-0 \
            libsm6 \
            libxext6 \
            libxrender-dev \
            libgomp1
        print_success "System dependencies installed"
        ;;
    "redhat"|"centos"|"fedora")
        sudo yum install -y \
            mesa-libGL \
            glib2 \
            libSM \
            libXext \
            libXrender \
            libgomp
        print_success "System dependencies installed"
        ;;
esac

# Create necessary directories
print_status "Creating project directories..."
mkdir -p results/reports
mkdir -p results/logs
mkdir -p results/exports
mkdir -p evidence
mkdir -p forensic_workspace/temp
mkdir -p forensic_workspace/backups
mkdir -p datasets/ground_truth
mkdir -p datasets/social_media
mkdir -p datasets/manipulated

print_success "Project directories created"

# Set directory permissions
print_status "Setting directory permissions..."
chmod 755 results
chmod 755 evidence
chmod 700 forensic_workspace

print_success "Directory permissions set"

# Verify installations
print_status "Verifying installations..."

# Verify Python packages
echo "Python packages:"
if $PYTHON_CMD -c "import PIL, exifread, numpy, pandas, yaml; print('✓ Core packages installed')" 2>/dev/null; then
    print_success "Python packages verified"
else
    print_error "Some Python packages failed to install"
    exit 1
fi

# Verify ExifTool
echo -n "ExifTool: "
if command_exists exiftool; then
    EXIFTOOL_VERSION=$(exiftool -ver 2>/dev/null || echo "Unknown")
    echo "✓ v$EXIFTOOL_VERSION"
else
    print_warning "ExifTool not found in PATH"
    echo "  Manual installation may be required for full functionality"
fi

# Verify OpenCV
echo -n "OpenCV: "
if $PYTHON_CMD -c "import cv2; print(f'✓ v{cv2.__version__}')" 2>/dev/null; then
    print_success "OpenCV verified"
else
    print_warning "OpenCV not installed or has issues"
fi

# Create configuration file
print_status "Creating default configuration..."
if [ ! -f "config/default_config.yaml" ]; then
    cp config/default_config.yaml.example config/default_config.yaml 2>/dev/null || \
    echo "Creating minimal config file..."
    cat > config/default_config.yaml << EOF
# MetaForensicAI Configuration
system:
  name: "MetaForensicAI"
  version: "1.0.0"
  mode: "forensic"

forensic:
  read_only: true
  hash_algorithms:
    - "sha256"
    - "sha3_256"

analysis:
  enable_timestamp_analysis: true
  enable_platform_detection: true

reporting:
  generate_pdf: true
  generate_json: true
  output_dir: "./results/reports"
EOF
    print_success "Configuration file created"
else
    print_warning "Configuration file already exists"
fi

# Run system test
print_status "Running system test..."
if $PYTHON_CMD -c "
import sys
sys.path.insert(0, '.')
try:
    from metaforensicai import validate_environment
    results = validate_environment()
    if results['overall']['status'] == 'PASS':
        print('✓ System test passed')
    else:
        print('⚠ System test warnings')
        for comp, info in results.items():
            if comp != 'overall' and info['status'] != 'PASS':
                print(f'  • {comp}: {info['message']}')
except Exception as e:
    print(f'✗ System test failed: {e}')
    sys.exit(1)
"; then
    print_success "System test completed"
else
    print_warning "System test encountered issues"
fi

# Create setup completion file
cat > .installation_complete << EOF
MetaForensicAI Installation Complete
====================================
Installation Date: $(date)
Python Version: $PYTHON_VERSION
OS Type: $OS_TYPE
ExifTool Version: $EXIFTOOL_VERSION

Next Steps:
1. Activate virtual environment: source venv/bin/activate
2. Test the system: python -m src.main --help
3. Analyze an image: python -m src.main --image path/to/image.jpg
4. View documentation: docs/README.md

For support:
• GitHub Issues: https://github.com/meteforensicai/MetaForensicAI/issues
• Documentation: https://meteforensicai.readthedocs.io/
EOF

print_status ""
echo "================================================"
echo "   Installation Summary"
echo "================================================"
echo ""
echo "✅ Python environment: $PYTHON_VERSION"
echo "✅ Virtual environment: venv/"
echo "✅ Python packages: Installed"
echo "✅ ExifTool: $(command_exists exiftool && echo "Installed ($EXIFTOOL_VERSION)" || echo "Not found")"
echo "✅ Project directories: Created"
echo "✅ Configuration: config/default_config.yaml"
echo ""
echo "Installation completed!"
echo ""
echo "To activate the virtual environment:"
echo "  source venv/bin/activate"
echo ""
echo "To run the system:"
echo "  python -m src.main --help"
echo ""
echo "For interactive mode:"
echo "  python -m src.main --image evidence.jpg --interactive"
echo ""
echo "Installation details saved to: .installation_complete"
echo "================================================"

# Exit with success
exit 0