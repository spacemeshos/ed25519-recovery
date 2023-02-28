package pure25519

import (
	"embed"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

//go:embed *
var pure25519FS embed.FS

type Pure25519 struct {
	dir string
}

func New() (Pure25519, error) {
	tmp, err := os.MkdirTemp("", "pure25519")
	if err != nil {
		return Pure25519{}, err
	}

	err = fs.WalkDir(pure25519FS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// copy all files
		if !d.IsDir() {
			file, err := pure25519FS.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			dst, err := os.Create(filepath.Join(tmp, path))
			if err != nil {
				return err
			}
			defer dst.Close()

			io.Copy(dst, file)
		}
		return nil
	})
	if err != nil {
		return Pure25519{}, err
	}

	// install python dependencies
	cmd := exec.Command("bash", "-c", "pip install -r ./requirements.txt")
	cmd.Dir = tmp
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println(out)
		return Pure25519{}, err
	}

	return Pure25519{dir: tmp}, nil
}

func (p Pure25519) Sign(msg []byte, seed []byte) ([]byte, error) {
	py := fmt.Sprintf("'import ed25519_ref; ed25519_ref.go_sign2(\"%s\", \"%s\")'", hex.EncodeToString(msg), hex.EncodeToString(seed))
	cmd := exec.Command("bash", "-c", "python3 -c "+py)
	cmd.Dir = p.dir

	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("python command failed: %w", err)
	}

	return hex.DecodeString(strings.TrimSpace(string(out)))
}

func (p Pure25519) Extract(msg []byte, sig []byte) ([]byte, error) {
	py := fmt.Sprintf("'import ed25519_ref; ed25519_ref.go_extract_pk(\"%s\", \"%s\")'", hex.EncodeToString(sig), hex.EncodeToString(msg))
	cmd := exec.Command("bash", "-c", "python3 -c "+py)
	cmd.Dir = p.dir

	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("python command failed: %w", err)
	}

	return hex.DecodeString(strings.TrimSpace(string(out)))
}

func (p Pure25519) Derive(seed []byte, salt []byte, index uint64) ([]byte, error) {
	py := fmt.Sprintf("'import ed25519_ref; ed25519_ref.go_derive(\"%s\", \"%s\", %d)'", hex.EncodeToString(seed), hex.EncodeToString(salt), index)
	cmd := exec.Command("bash", "-c", "python3 -c "+py)
	cmd.Dir = p.dir

	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("python command failed: %w", err)
	}

	return hex.DecodeString(strings.TrimSpace(string(out)))
}
