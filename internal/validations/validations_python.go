package validations

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"k8s.io/klog/v2"

	"github.com/openshift/check-payload/internal/python"
	"github.com/openshift/check-payload/internal/types"
)

// PythonCryptoValidation holds the validation result for a cryptography installation
type PythonCryptoValidation struct {
	Installation *python.CryptographyInstallation
	IsCompliant  bool
	Violations   []PythonCryptoViolation
}

// PythonCryptoViolation represents a FIPS compliance violation
type PythonCryptoViolation struct {
	ModulePath string
	Error      error
	Reason     string
	LinkedLibs []string // Libraries linked by the module
}

// ValidatePythonCryptography validates all cryptography installations in the mount path
func ValidatePythonCryptography(ctx context.Context, mountPath string) []*PythonCryptoValidation {
	klog.V(1).InfoS("validating Python cryptography installations", "mountPath", mountPath)

	// Step 1: Find all Python installations
	pythonInstalls, err := python.FindPythonInstallations(ctx, mountPath)
	if err != nil {
		klog.ErrorS(err, "failed to find Python installations")
		return nil
	}

	if len(pythonInstalls) == 0 {
		klog.V(1).Info("no Python installations found")
		return nil
	}

	klog.V(1).InfoS("found Python installations", "count", len(pythonInstalls))

	// Step 2: Find all cryptography installations
	cryptoInstalls, err := python.FindCryptographyInstallations(ctx, mountPath, pythonInstalls)
	if err != nil {
		klog.ErrorS(err, "failed to find cryptography installations")
		return nil
	}

	if len(cryptoInstalls) == 0 {
		klog.V(1).Info("no cryptography installations found")
		return nil
	}

	klog.V(1).InfoS("found cryptography installations", "count", len(cryptoInstalls))

	// Step 3: Validate each cryptography installation
	var validations []*PythonCryptoValidation

	for i := range cryptoInstalls {
		cryptoInstall := &cryptoInstalls[i]
		validation := validateCryptographyInstallation(ctx, mountPath, cryptoInstall)
		validations = append(validations, validation)
	}

	return validations
}

// validateCryptographyInstallation validates a single cryptography installation
func validateCryptographyInstallation(ctx context.Context, mountPath string, install *python.CryptographyInstallation) *PythonCryptoValidation {
	validation := &PythonCryptoValidation{
		Installation: install,
		IsCompliant:  true,
		Violations:   []PythonCryptoViolation{},
	}

	// If this is a system package (RPM), consider it compliant
	if install.IsSystemPkg {
		klog.V(1).InfoS("cryptography is system package, assuming FIPS compliant",
			"path", install.PackagePath,
			"rpm", install.RPM)
		return validation
	}

	// For non-system packages (pip installed), check each native module
	if len(install.NativeModules) == 0 {
		// No native modules found - this is unusual but not necessarily a violation
		klog.V(1).InfoS("no native modules found in cryptography installation",
			"path", install.PackagePath)
		validation.IsCompliant = true
		return validation
	}

	// Validate each native module
	for _, modulePath := range install.NativeModules {
		fullModulePath := filepath.Join(mountPath, install.PackagePath, modulePath)

		violation := validateCryptoModule(ctx, mountPath, fullModulePath)
		if violation != nil {
			validation.IsCompliant = false
			violation.ModulePath = modulePath
			validation.Violations = append(validation.Violations, *violation)
		}
	}

	if !validation.IsCompliant {
		klog.InfoS("cryptography installation has FIPS violations",
			"path", install.PackagePath,
			"violations", len(validation.Violations))
	} else {
		klog.V(1).InfoS("cryptography installation is FIPS compliant",
			"path", install.PackagePath)
	}

	return validation
}

// validateCryptoModule checks a single native module for FIPS compliance
func validateCryptoModule(ctx context.Context, mountPath, modulePath string) *PythonCryptoViolation {
	// Use ldd to check dynamic linkage
	linkedLibs, err := checkDynamicLinkage(ctx, modulePath)
	if err != nil {
		return &PythonCryptoViolation{
			ModulePath: modulePath,
			Error:      err,
			Reason:     "failed to check dynamic linkage",
			LinkedLibs: nil,
		}
	}

	// Check if the module links to system libcrypto
	hasSystemLibcrypto := false
	hasNonSystemLibcrypto := false
	var foundLibcryptoPath string

	for _, lib := range linkedLibs {
		if strings.Contains(lib, "libcrypto.so") || strings.Contains(lib, "libssl.so") {
			if isSystemLibcrypto(lib) {
				hasSystemLibcrypto = true
				foundLibcryptoPath = lib
			} else {
				hasNonSystemLibcrypto = true
				foundLibcryptoPath = lib
			}
		}
	}

	// Violation conditions:
	// 1. No libcrypto linkage at all (using bundled Rust crypto)
	// 2. Links to non-system libcrypto (bundled OpenSSL)

	if !hasSystemLibcrypto && !hasNonSystemLibcrypto {
		return &PythonCryptoViolation{
			ModulePath: modulePath,
			Error:      types.ErrPythonCryptoNotLinkedToSystem,
			Reason:     "module does not link to any libcrypto (likely using bundled Rust cryptography)",
			LinkedLibs: linkedLibs,
		}
	}

	if hasNonSystemLibcrypto {
		return &PythonCryptoViolation{
			ModulePath: modulePath,
			Error:      types.ErrPythonCryptoBundledLibrary,
			Reason:     fmt.Sprintf("module links to non-system libcrypto: %s", foundLibcryptoPath),
			LinkedLibs: linkedLibs,
		}
	}

	// If we reach here, the module links to system libcrypto - compliant
	return nil
}

// checkDynamicLinkage uses ldd to check library linkage
func checkDynamicLinkage(ctx context.Context, modulePath string) ([]string, error) {
	// Run ldd on the module
	cmd := exec.CommandContext(ctx, "ldd", modulePath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		klog.V(2).InfoS("ldd command failed", "path", modulePath, "error", err, "stderr", stderr.String())
		// ldd can fail for statically linked binaries or non-ELF files
		// Return empty list rather than error
		return []string{}, nil
	}

	// Parse ldd output
	// Example lines:
	//   libcrypto.so.3 => /usr/lib64/libcrypto.so.3 (0x00007f...)
	//   /lib64/ld-linux-x86-64.so.2 (0x00007f...)
	//   linux-vdso.so.1 (0x00007f...)

	var linkedLibs []string
	lines := strings.Split(stdout.String(), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse the line to extract library paths
		// Format: "libname => /path/to/lib (address)" or "/path/to/lib (address)"
		if strings.Contains(line, "=>") {
			parts := strings.Split(line, "=>")
			if len(parts) >= 2 {
				pathPart := strings.TrimSpace(parts[1])
				// Remove the address part in parentheses
				if idx := strings.Index(pathPart, "("); idx > 0 {
					pathPart = strings.TrimSpace(pathPart[:idx])
				}
				if pathPart != "" && pathPart != "not found" {
					linkedLibs = append(linkedLibs, pathPart)
				}
			}
		} else if strings.HasPrefix(line, "/") {
			// Direct path without =>
			pathPart := line
			if idx := strings.Index(pathPart, "("); idx > 0 {
				pathPart = strings.TrimSpace(pathPart[:idx])
			}
			if pathPart != "" {
				linkedLibs = append(linkedLibs, pathPart)
			}
		}
	}

	return linkedLibs, nil
}

// isSystemLibcrypto checks if a library path points to system libcrypto
func isSystemLibcrypto(libPath string) bool {
	// System libraries are typically in:
	// - /usr/lib64/
	// - /usr/lib/
	// - /lib64/
	// - /lib/

	systemPaths := []string{
		"/usr/lib64/",
		"/usr/lib/",
		"/lib64/",
		"/lib/",
	}

	for _, sysPath := range systemPaths {
		if strings.HasPrefix(libPath, sysPath) {
			return true
		}
	}

	// Not in a system path - likely bundled
	return false
}

