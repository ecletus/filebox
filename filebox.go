package filebox

import (
	"encoding/json"
	"fmt"
	"github.com/qor/admin"
	"github.com/qor/roles"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
)

// Filebox is a object save download folder path and a specific download file used to set permission
type Filebox struct {
	Dir      string
	FilePath string
	Auth     admin.Auth
}

type File struct {
	FilePath string
	Roles    []string
	Dir      *Dir
}

type Dir struct {
	DirPath string
	Roles   []string
}

func (filebox *Filebox) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	filebox.Download(w, req)
}

// New a filebox struct with download dir
func New(dir string) *Filebox {
	return &Filebox{Dir: dir}
}

// MountTo will mount `/downloads` to mux
func (filebox *Filebox) MountTo(mux *http.ServeMux) {
	mux.Handle("/downloads/", filebox)
}

// SetAuth will set a admin.Auth struct to Filebox, used to get current user's role
func (filebox *Filebox) SetAuth(auth admin.Auth) {
	filebox.Auth = auth
}

func (filebox *Filebox) AccessFile(filePath string, roles ...string) *File {
	file := &File{FilePath: path.Join(filebox.Dir, filePath), Roles: roles}
	file.Dir = filebox.AccessDir(filepath.Dir(filePath), roles...)
	return file
}

func (f *File) Read() (io.ReadSeeker, error) {
	if f.HasPermission() {
		return os.Open(f.FilePath)
	}
	return nil, fmt.Errorf("Doesn't have permission to read the file")
}

func (file *File) Write(reader io.Reader) (err error) {
	var dst *os.File
	if _, err = os.Stat(file.FilePath); os.IsNotExist(err) {
		err = os.MkdirAll(filepath.Dir(file.FilePath), os.ModePerm)
	}
	if err != nil {
		return err
	}
	if dst, err = os.Create(file.FilePath); err == nil {
		_, err = io.Copy(dst, reader)
	}
	return err
}

func (file *File) SetPermission(permission *roles.Permission) (err error) {
	jsonVal, err := json.Marshal(permission)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(file.metaFilePath(), jsonVal, 0644)
	return err
}

func (file *File) HasPermission() bool {
	if _, err := os.Stat(file.metaFilePath()); !os.IsNotExist(err) {
		bytes, err := ioutil.ReadFile(file.metaFilePath())
		if err != nil {
			return false
		}
		permission := &roles.Permission{}
		err = json.Unmarshal(bytes, permission)
		if err == nil {
			var hasPermission bool
			for _, role := range file.Roles {
				if permission.HasPermission(roles.Read, role) {
					hasPermission = true
					break
				}
			}
			return hasPermission
		}
	}
	return file.Dir.HasPermission()
}

func (file *File) metaFilePath() string {
	fileName := filepath.Base(file.FilePath)
	dir := filepath.Dir(file.FilePath)
	return path.Join(dir, fileName+".meta")
}

func (filebox *Filebox) AccessDir(dirPath string, roles ...string) *Dir {
	return &Dir{DirPath: path.Join(filebox.Dir, dirPath), Roles: roles}
}

func (dir *Dir) WriteFile(fileName string, reader io.Reader) (err error) {
	err = dir.createIfNoExist()
	var dst *os.File
	if dst, err = os.Create(path.Join(dir.DirPath, fileName)); err == nil {
		_, err = io.Copy(dst, reader)
	}
	return err
}

func (dir *Dir) SetPermission(permission *roles.Permission) (err error) {
	err = dir.createIfNoExist()
	jsonVal, err := json.Marshal(permission)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(dir.metaDirPath(), jsonVal, 0644)
	return err
}

func (dir *Dir) HasPermission() bool {
	if _, err := os.Stat(dir.metaDirPath()); !os.IsNotExist(err) {
		bytes, err := ioutil.ReadFile(dir.metaDirPath())
		if err != nil {
			return false
		}
		permission := &roles.Permission{}
		if json.Unmarshal(bytes, permission); err == nil {
			var hasPermission bool
			for _, role := range dir.Roles {
				if permission.HasPermission(roles.Read, role) {
					hasPermission = true
					break
				}
			}
			return hasPermission
		}
	}
	return true
}

func (dir *Dir) createIfNoExist() (err error) {
	if _, err = os.Stat(dir.DirPath); os.IsNotExist(err) {
		err = os.MkdirAll(dir.DirPath, os.ModePerm)
	}
	return err
}

func (dir *Dir) metaDirPath() string {
	return path.Join(dir.DirPath, ".meta")
}