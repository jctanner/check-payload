package python

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"k8s.io/klog/v2"
)

// PythonInstallation represents a Python interpreter installation
type PythonInstallation struct {
	PythonPath   string   // e.g., "/usr/bin/python3.12"
	Version      string   // e.g., "3.12"
	SitePackages []string // Paths to site-packages directories
}

// CryptographyInstallation represents a cryptography package installation
type CryptographyInstallation struct {
	PythonVersion string   // Associated Python version
	PackagePath   string   // Path to cryptography package
	Version       string   // cryptography version
	NativeModules []string // Paths to .so files
	IsSystemPkg   bool     // Installed via system package manager
	RPM           string   // RPM name if system package
}

var (
	// Common Python binary patterns
	pythonBinaryRegex = regexp.MustCompile(`^python\d+(\.\d+)?$`)

	// Common site-packages locations
	sitePackagesPaths = []string{
		"usr/lib/python*/site-packages",
		"usr/lib64/python*/site-packages",
		"usr/local/lib/python*/site-packages",
	}

	// Native module patterns in cryptography
	cryptoNativeModules = []string{
		"_rust.abi3.so",
		"_openssl.abi3.so",
		"_rust.*.so",
		"_openssl.*.so",
	}
)

// FindPythonInstallations discovers all Python installations in the mount path
func FindPythonInstallations(ctx context.Context, mountPath string) ([]PythonInstallation, error) {
	klog.V(1).InfoS("discovering Python installations", "mountPath", mountPath)

	var pythonInstalls []PythonInstallation
	seen := make(map[string]bool) // Track unique Python paths

	// Search common binary locations
	searchPaths := []string{
		filepath.Join(mountPath, "usr", "bin"),
		filepath.Join(mountPath, "usr", "local", "bin"),
		filepath.Join(mountPath, "bin"),
	}

	for _, searchPath := range searchPaths {
		entries, err := os.ReadDir(searchPath)
		if err != nil {
			// Directory might not exist, continue
			continue
		}

		for _, entry := range entries {
			// Check if it matches python binary pattern
			if !pythonBinaryRegex.MatchString(entry.Name()) {
				continue
			}

			pythonPath := filepath.Join(searchPath, entry.Name())
			relativePath := strings.TrimPrefix(pythonPath, mountPath)

			// Skip if we've already seen this Python
			if seen[relativePath] {
				continue
			}
			seen[relativePath] = true

			// Extract version from binary name
			version := extractVersionFromBinary(entry.Name())
			if version == "" {
				klog.V(2).InfoS("could not extract version from Python binary", "name", entry.Name())
				continue
			}

			// Find site-packages for this Python version
			sitePackages := findSitePackages(mountPath, version)

			pythonInstall := PythonInstallation{
				PythonPath:   relativePath,
				Version:      version,
				SitePackages: sitePackages,
			}

			klog.V(1).InfoS("found Python installation", "path", relativePath, "version", version, "sitePackages", len(sitePackages))
			pythonInstalls = append(pythonInstalls, pythonInstall)
		}
	}

	// Also search for virtual environments
	venvInstalls := findVirtualEnvPython(ctx, mountPath)
	pythonInstalls = append(pythonInstalls, venvInstalls...)

	return pythonInstalls, nil
}

// FindCryptographyInstallations finds all cryptography package installations
func FindCryptographyInstallations(ctx context.Context, mountPath string, pythonInstalls []PythonInstallation) ([]CryptographyInstallation, error) {
	klog.V(1).InfoS("discovering cryptography installations", "mountPath", mountPath)

	var cryptoInstalls []CryptographyInstallation

	// Build a list of all site-packages directories to search
	var sitePackageDirs []string
	pythonVersions := make(map[string]string) // Map site-packages path to Python version

	for _, py := range pythonInstalls {
		for _, sp := range py.SitePackages {
			sitePackageDirs = append(sitePackageDirs, sp)
			pythonVersions[sp] = py.Version
		}
	}

	// Search each site-packages directory for cryptography
	for _, sp := range sitePackageDirs {
		fullPath := filepath.Join(mountPath, sp)
		if _, err := os.Stat(fullPath); err != nil {
			continue
		}

		entries, err := os.ReadDir(fullPath)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			// Look for cryptography package directory
			if entry.IsDir() && entry.Name() == "cryptography" {
				cryptoPath := filepath.Join(sp, "cryptography")
				fullCryptoPath := filepath.Join(mountPath, cryptoPath)

				// Get version from dist-info
				version := getCryptographyVersion(filepath.Dir(fullCryptoPath))

				// Find native modules
				nativeModules := getNativeModules(fullCryptoPath)

				// Check if this is a system package
				isSystemPkg, rpmName := isSystemPackage(ctx, mountPath, cryptoPath)

				cryptoInstall := CryptographyInstallation{
					PythonVersion: pythonVersions[sp],
					PackagePath:   cryptoPath,
					Version:       version,
					NativeModules: nativeModules,
					IsSystemPkg:   isSystemPkg,
					RPM:           rpmName,
				}

				klog.V(1).InfoS("found cryptography installation",
					"path", cryptoPath,
					"version", version,
					"pythonVersion", cryptoInstall.PythonVersion,
					"isSystemPkg", isSystemPkg,
					"nativeModules", len(nativeModules))

				cryptoInstalls = append(cryptoInstalls, cryptoInstall)
			}
		}
	}

	return cryptoInstalls, nil
}

// GetNativeModules extracts native .so files from a cryptography installation
func GetNativeModules(cryptoInstallPath string) ([]string, error) {
	return getNativeModules(cryptoInstallPath), nil
}

// extractVersionFromBinary extracts Python version from binary name
// e.g., "python3.12" -> "3.12", "python3" -> "3"
func extractVersionFromBinary(name string) string {
	// Remove "python" prefix
	version := strings.TrimPrefix(name, "python")
	return version
}

// findSitePackages finds site-packages directories for a given Python version
func findSitePackages(mountPath, version string) []string {
	var sitePackages []string

	// Common patterns for site-packages
	patterns := []string{
		fmt.Sprintf("usr/lib/python%s/site-packages", version),
		fmt.Sprintf("usr/lib64/python%s/site-packages", version),
		fmt.Sprintf("usr/local/lib/python%s/site-packages", version),
	}

	for _, pattern := range patterns {
		fullPath := filepath.Join(mountPath, pattern)
		if stat, err := os.Stat(fullPath); err == nil && stat.IsDir() {
			sitePackages = append(sitePackages, pattern)
		}
	}

	return sitePackages
}

// findVirtualEnvPython searches for Python in virtual environments
func findVirtualEnvPython(ctx context.Context, mountPath string) []PythonInstallation {
	var venvInstalls []PythonInstallation

	// Walk the filesystem looking for pyvenv.cfg or activate scripts that indicate a venv
	// This is more reliable than glob patterns
	err := filepath.WalkDir(mountPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return filepath.SkipDir
		}

		// Skip deep nesting to avoid performance issues
		relPath := strings.TrimPrefix(path, mountPath)
		depth := strings.Count(relPath, "/")
		if depth > 5 {
			return filepath.SkipDir
		}

		// Skip common non-venv directories
		if d.IsDir() {
			name := d.Name()
			if name == "proc" || name == "sys" || name == "dev" || name == ".git" {
				return filepath.SkipDir
			}
		}

		// Look for pyvenv.cfg which indicates a virtualenv
		if !d.IsDir() && d.Name() == "pyvenv.cfg" {
			venvRoot := filepath.Dir(path)
			pythonBinDir := filepath.Join(venvRoot, "bin")

			// Find Python binaries in the bin directory
			entries, err := os.ReadDir(pythonBinDir)
			if err != nil {
				return nil
			}

			for _, entry := range entries {
				if pythonBinaryRegex.MatchString(entry.Name()) {
					pythonPath := filepath.Join(pythonBinDir, entry.Name())
					relativePythonPath := strings.TrimPrefix(pythonPath, mountPath)
					
					version := extractVersionFromBinary(entry.Name())
					if version == "" {
						continue
					}

					// Find site-packages relative to venv
					relVenvRoot := strings.TrimPrefix(venvRoot, mountPath)
					sitePackages := findVenvSitePackages(mountPath, relVenvRoot, version)

					if len(sitePackages) > 0 {
						klog.V(2).InfoS("found venv Python", "path", relativePythonPath, "version", version, "sitePackages", sitePackages)
						venvInstalls = append(venvInstalls, PythonInstallation{
							PythonPath:   relativePythonPath,
							Version:      version,
							SitePackages: sitePackages,
						})
						break // Only need one Python per venv
					}
				}
			}
		}

		return nil
	})

	if err != nil {
		klog.V(2).InfoS("error walking for venvs", "error", err)
	}

	return venvInstalls
}

// findVenvSitePackages finds site-packages within a virtual environment
// Returns only site-packages directories that actually exist
func findVenvSitePackages(mountPath, venvRoot, version string) []string {
	var sitePackages []string

	patterns := []string{
		filepath.Join(venvRoot, "lib", fmt.Sprintf("python%s", version), "site-packages"),
		filepath.Join(venvRoot, "lib64", fmt.Sprintf("python%s", version), "site-packages"),
	}

	for _, pattern := range patterns {
		fullPath := filepath.Join(mountPath, pattern)
		if stat, err := os.Stat(fullPath); err == nil && stat.IsDir() {
			sitePackages = append(sitePackages, pattern)
		}
	}

	return sitePackages
}

// getCryptographyVersion attempts to read cryptography version from dist-info
func getCryptographyVersion(sitePackagesPath string) string {
	// Look for cryptography-*.dist-info directory
	entries, err := os.ReadDir(sitePackagesPath)
	if err != nil {
		return "unknown"
	}

	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "cryptography-") && strings.HasSuffix(entry.Name(), ".dist-info") {
			// Extract version from directory name
			// e.g., "cryptography-42.0.0.dist-info" -> "42.0.0"
			name := entry.Name()
			name = strings.TrimPrefix(name, "cryptography-")
			name = strings.TrimSuffix(name, ".dist-info")
			return name
		}
	}

	return "unknown"
}

// getNativeModules finds native .so files in the cryptography package
func getNativeModules(cryptoPath string) []string {
	var modules []string

	// Look in hazmat/bindings/ subdirectory
	bindingsPath := filepath.Join(cryptoPath, "hazmat", "bindings")

	err := filepath.WalkDir(bindingsPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // Continue on errors
		}

		if d.IsDir() {
			return nil
		}

		// Check if it's a .so file
		if strings.HasSuffix(d.Name(), ".so") {
			relativePath := strings.TrimPrefix(path, cryptoPath)
			relativePath = strings.TrimPrefix(relativePath, "/")
			modules = append(modules, relativePath)
		}

		return nil
	})

	if err != nil {
		klog.V(2).InfoS("error walking cryptography directory", "path", cryptoPath, "error", err)
	}

	return modules
}

// isSystemPackage checks if a path is owned by a system package (RPM)
func isSystemPackage(ctx context.Context, mountPath, path string) (bool, string) {
	// This would use RPM query to check if the file is owned by an RPM
	// For now, we'll use a simple heuristic: if it's in /usr/lib64 or /usr/lib
	// and not in a venv-like path, assume it's a system package

	if strings.Contains(path, "venv") || strings.Contains(path, "env") || strings.Contains(path, ".local") {
		return false, ""
	}

	if strings.HasPrefix(path, "usr/lib64/python") || strings.HasPrefix(path, "usr/lib/python") {
		// Could query RPM here for the exact package name
		// For now, return a generic name
		return true, "python-cryptography"
	}

	return false, ""
}

