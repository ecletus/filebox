package filebox

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"context"

	"github.com/ecletus/admin"
	"github.com/ecletus/roles"
	"github.com/moisespsena-go/xroute"
)

// Filebox is a based object contains download folder path and admin.Auth used to get current user
type Filebox struct {
	BaseDir string
	Router  *xroute.Mux
	Auth    admin.Auth
	prefix  string
	Admin   *admin.Admin
}

// File is a object to access a specific file
type File struct {
	FilePath string
	Roles    []string
	Dir      *Dir
	Filebox  *Filebox
}

// Dir is a object to access a specific directory
type Dir struct {
	DirPath string
	Roles   []string
	Filebox *Filebox
}

// New a filebox struct
func New(dir string) *Filebox {
	f := &Filebox{BaseDir: dir, Router: xroute.NewMux("qor:filebox")}
	f.Router.Handle("/", f.Download)
	return f
}

// SetAuth will set a admin.Auth struct to Filebox, used to get current user's role
func (filebox *Filebox) SetAuth(auth admin.Auth) {
	filebox.Auth = auth
}

// AccessFile will return a specific File object
func (filebox *Filebox) AccessFile(filePath string, roles ...string) *File {
	file := &File{FilePath: filepath.Join(filebox.BaseDir, filePath), Roles: roles, Filebox: filebox}
	file.Dir = filebox.AccessDir(filepath.Dir(filePath), roles...)
	return file
}

// Read will get a io reader for a specific file
func (f *File) Read(ctx context.Context) (io.ReadSeeker, error) {
	if f.HasPermission(ctx, roles.Read) {
		return os.Open(f.FilePath)
	}
	return nil, roles.ErrPermissionDenied
}

// Write used to store reader's content to a file
func (f *File) Write(ctx context.Context, reader io.Reader) (err error) {
	if f.HasPermission(ctx, roles.Update) {
		var dst *os.File
		if _, err = os.Stat(f.FilePath); os.IsNotExist(err) {
			err = os.MkdirAll(filepath.Dir(f.FilePath), os.ModePerm)
		}

		if err == nil {
			if dst, err = os.Create(f.FilePath); err == nil {
				_, err = io.Copy(dst, reader)
			}
		}
		return err
	}
	return roles.ErrPermissionDenied
}

// SetPermission used to set a Permission to file
func (f *File) SetPermission(permission *roles.Permission) (err error) {
	jsonVal, err := json.Marshal(permission)
	if err == nil {
		err = ioutil.WriteFile(f.metaFilePath(), jsonVal, 0644)
	}
	return err
}

// HasPermission used to check current user whether have permission to access file
func (f *File) HasPermission(ctx context.Context, mode roles.PermissionMode) bool {
	if _, err := os.Stat(f.metaFilePath()); !os.IsNotExist(err) {
		return hasPermission(ctx, f.metaFilePath(), mode, f.Roles)
	}
	return f.Dir.HasPermission(ctx, mode)
}

func (f *File) metaFilePath() string {
	fileName := filepath.Base(f.FilePath)
	dir := filepath.Dir(f.FilePath)
	return filepath.Join(dir, fileName+".meta")
}

// AccessDir will return a specific Dir object
func (filebox *Filebox) AccessDir(dirPath string, roles ...string) *Dir {
	return &Dir{DirPath: filepath.Join(filebox.BaseDir, dirPath), Roles: roles, Filebox: filebox}
}

// WriteFile writes data to a file named by filename. If the file does not exist, WriteFile will create a new file
func (dir *Dir) WriteFile(ctx context.Context, fileName string, reader io.Reader) (file *File, err error) {
	if err = dir.createIfNoExist(); err == nil {
		relativeDir := strings.TrimPrefix(dir.DirPath, dir.Filebox.BaseDir)
		file = dir.Filebox.AccessFile(filepath.Join(relativeDir, fileName), dir.Roles...)
		err = file.Write(ctx, reader)
	}
	return
}

// SetPermission used to set a Permission to directory
func (dir *Dir) SetPermission(permission *roles.Permission) (err error) {
	err = dir.createIfNoExist()
	jsonVal, err := json.Marshal(permission)
	if err == nil {
		err = ioutil.WriteFile(dir.metaDirPath(), jsonVal, 0644)
	}
	return err
}

// HasPermission used to check current user whether have permission to access directory
func (dir *Dir) HasPermission(ctx context.Context, mode roles.PermissionMode) bool {
	return hasPermission(ctx, dir.metaDirPath(), mode, dir.Roles)
}

func (dir *Dir) createIfNoExist() (err error) {
	if _, err = os.Stat(dir.DirPath); os.IsNotExist(err) {
		err = os.MkdirAll(dir.DirPath, os.ModePerm)
	}
	return err
}

func (dir *Dir) metaDirPath() string {
	return filepath.Join(dir.DirPath, ".meta")
}

func hasPermission(ctx context.Context, metaFilePath string, mode roles.PermissionMode, currentRoles []string) bool {
	if _, err := os.Stat(metaFilePath); !os.IsNotExist(err) {
		if bytes, err := ioutil.ReadFile(metaFilePath); err == nil {
			permission := &roles.Permission{}
			ctx := admin.ContextFromContext(ctx)
			var oldRoles = ctx.Roles
			ctx.Roles = roles.NewRoles(currentRoles...)
			defer func() {
				ctx.Roles = oldRoles
			}()
			if json.Unmarshal(bytes, permission); err == nil {
				return ctx.HasRolePermission(permission, mode)
			}
		}
		return false
	}
	return true
}
