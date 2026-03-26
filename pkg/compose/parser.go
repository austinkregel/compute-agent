package compose

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/compose-spec/compose-go/v2/cli"
	"github.com/compose-spec/compose-go/v2/types"
)

// Scanner finds and parses docker-compose files within allowed roots.
type Scanner struct {
	allowedRoots []string
}

// NewScanner creates a Scanner restricted to the given root directories.
func NewScanner(allowedRoots []string) *Scanner {
	return &Scanner{allowedRoots: allowedRoots}
}

// ScanDirectory finds docker-compose files in dir and extracts service names.
func (s *Scanner) ScanDirectory(dir string) (*ScanResult, error) {
	if err := s.validateRoot(dir); err != nil {
		return nil, err
	}

	result := &ScanResult{Dir: dir}

	patterns := []string{
		"docker-compose.yml",
		"docker-compose.yaml",
		"docker-compose*.yml",
		"docker-compose*.yaml",
		"compose.yml",
		"compose.yaml",
	}

	seen := map[string]struct{}{}
	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			continue
		}
		for _, m := range matches {
			abs, err := filepath.Abs(m)
			if err != nil {
				continue
			}
			if _, ok := seen[abs]; ok {
				continue
			}
			seen[abs] = struct{}{}

			cf := ComposeFile{
				Path: abs,
				Name: filepath.Base(abs),
			}
			cf.Services = quickExtractServiceNames(abs)
			cf.Includes = quickExtractIncludes(abs)
			result.Files = append(result.Files, cf)
		}
	}
	return result, nil
}

// ParseFile fully parses a compose file using the compose-go library.
func (s *Scanner) ParseFile(path string) (*ParseResult, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve path: %w", err)
	}
	if err := s.validateRoot(filepath.Dir(abs)); err != nil {
		return nil, err
	}

	result := &ParseResult{File: abs}

	opts, err := cli.NewProjectOptions(
		[]string{abs},
		cli.WithDotEnv,
		cli.WithInterpolation(true),
	)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}

	project, err := opts.LoadProject(context.Background())
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}

	for _, svc := range project.Services {
		ps := ParsedService{
			Name:        svc.Name,
			Image:       svc.Image,
			Restart:     svc.Restart,
			NetworkMode: svc.NetworkMode,
		}

		for _, p := range svc.Ports {
			ps.Ports = append(ps.Ports, fmt.Sprintf("%s:%s:%d/%s",
				p.HostIP, p.Published, p.Target, p.Protocol))
		}
		for _, v := range svc.Volumes {
			ps.Volumes = append(ps.Volumes, v.String())
		}
		if len(svc.Command) > 0 {
			ps.Command = []string(svc.Command)
		}
		if len(svc.Entrypoint) > 0 {
			ps.Entrypoint = []string(svc.Entrypoint)
		}
		for host, ips := range svc.ExtraHosts {
			for _, ip := range ips {
				ps.ExtraHosts = append(ps.ExtraHosts, host+":"+ip)
			}
		}
		for _, d := range svc.Devices {
			ps.Devices = append(ps.Devices, d.Source+":"+d.Target)
		}

		if len(svc.Environment) > 0 {
			ps.Environment = map[string]string{}
			for k, v := range svc.Environment {
				if v != nil {
					ps.Environment[k] = *v
				}
			}
		}
		if len(svc.Labels) > 0 {
			ps.Labels = svc.Labels
		}

		if len(svc.DependsOn) > 0 {
			ps.DependsOn = map[string]ServiceDependency{}
			for name, dep := range svc.DependsOn {
				ps.DependsOn[name] = ServiceDependency{Condition: dep.Condition}
			}
		}

		if svc.HealthCheck != nil && !svc.HealthCheck.Disable {
			hc := &HealthCheckConfig{
				Disable: svc.HealthCheck.Disable,
			}
			hc.Test = svc.HealthCheck.Test
			if svc.HealthCheck.Interval != nil {
				hc.Interval = svc.HealthCheck.Interval.String()
			}
			if svc.HealthCheck.Timeout != nil {
				hc.Timeout = svc.HealthCheck.Timeout.String()
			}
			if svc.HealthCheck.StartPeriod != nil {
				hc.StartPeriod = svc.HealthCheck.StartPeriod.String()
			}
			if svc.HealthCheck.Retries != nil {
				hc.Retries = int(*svc.HealthCheck.Retries)
			}
			ps.HealthCheck = hc
		}

		if svc.Deploy != nil {
			dc := &DeployConfig{}
			if svc.Deploy.Replicas != nil {
				r := int(*svc.Deploy.Replicas)
				dc.Replicas = &r
			}
			if svc.Deploy.Resources.Limits != nil || svc.Deploy.Resources.Reservations != nil {
				rc := &ResourceConfig{}
				if svc.Deploy.Resources.Limits != nil {
					rc.Limits = convertResourceSpec(svc.Deploy.Resources.Limits)
				}
				if svc.Deploy.Resources.Reservations != nil {
					rc.Reservations = convertResourceSpec(svc.Deploy.Resources.Reservations)
				}
				dc.Resources = rc
			}
			ps.Deploy = dc
		}

		if len(svc.Networks) > 0 {
			for name := range svc.Networks {
				ps.Networks = append(ps.Networks, name)
			}
		}

		result.Services = append(result.Services, ps)
	}

	if len(project.Networks) > 0 {
		result.Networks = map[string]ParsedNetwork{}
		for name, net := range project.Networks {
			pn := ParsedNetwork{
				Driver:   net.Driver,
				Internal: net.Internal,
				External: bool(net.External),
			}
			result.Networks[name] = pn
		}
	}

	if len(project.Volumes) > 0 {
		result.Volumes = map[string]ParsedVolume{}
		for name, vol := range project.Volumes {
			pv := ParsedVolume{
				Driver:   vol.Driver,
				External: bool(vol.External),
			}
			result.Volumes[name] = pv
		}
	}

	return result, nil
}

func convertResourceSpec(r *types.Resource) *ResourceSpec {
	if r == nil {
		return nil
	}
	spec := &ResourceSpec{
		CPUs:   float64(r.NanoCPUs),
		Memory: fmt.Sprintf("%d", r.MemoryBytes),
	}
	for _, d := range r.Devices {
		spec.Devices = append(spec.Devices, DeviceSpec{
			Capabilities: d.Capabilities,
			Count:        int(d.Count),
			Driver:       d.Driver,
		})
	}
	return spec
}

func (s *Scanner) validateRoot(dir string) error {
	if len(s.allowedRoots) == 0 {
		return nil
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("resolve dir: %w", err)
	}
	for _, root := range s.allowedRoots {
		rootAbs, err := filepath.Abs(root)
		if err != nil {
			continue
		}
		if strings.HasPrefix(abs, rootAbs) {
			return nil
		}
	}
	return fmt.Errorf("directory %q is outside allowed roots", dir)
}

// quickExtractServiceNames reads a compose file quickly to extract service names
// without doing a full parse (for scan results).
func quickExtractServiceNames(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var services []string
	scanner := bufio.NewScanner(f)
	inServices := false
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "services:" {
			inServices = true
			continue
		}
		if inServices {
			// Top-level key (no leading whitespace or different section)
			if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
				break
			}
			// Service name: exactly 2 spaces of indent + name + colon
			if len(line) >= 3 && (line[0] == ' ' || line[0] == '\t') {
				// Check if this is a direct child (not deeply nested)
				stripped := strings.TrimLeft(line, " \t")
				indent := len(line) - len(stripped)
				if indent <= 4 && strings.HasSuffix(stripped, ":") || strings.Contains(stripped, ":") {
					name := strings.TrimRight(strings.SplitN(stripped, ":", 2)[0], " ")
					if name != "" && !strings.HasPrefix(name, "#") && !strings.HasPrefix(name, "-") {
						services = append(services, name)
					}
				}
			}
		}
	}
	return services
}

// quickExtractIncludes extracts include file paths from a compose file.
func quickExtractIncludes(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var includes []string
	scanner := bufio.NewScanner(f)
	inInclude := false
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "include:" {
			inInclude = true
			continue
		}
		if inInclude {
			if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
				break
			}
			if strings.HasPrefix(trimmed, "- ") {
				val := strings.TrimPrefix(trimmed, "- ")
				val = strings.Trim(val, "\"'")
				if val != "" {
					includes = append(includes, val)
				}
			}
		}
	}
	return includes
}
