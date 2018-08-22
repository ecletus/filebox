package filebox

import (
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/aghape/admin"
	"github.com/aghape/core"
	"github.com/aghape/roles"
	"github.com/aghape/common"
)

// Download is a handler will return a specific file
func (filebox *Filebox) Download(w http.ResponseWriter, req *http.Request) {
	var (
		currentUser common.User
		filePath    = strings.TrimPrefix(req.URL.Path, filebox.Router.Prefix())
		context     = &admin.Context{Context: &core.Context{Request: req, Writer: w}}
	)

	if auth := filebox.Auth; auth != nil {
		currentUser = auth.GetCurrentUser(context)
	}

	matchedRoles := roles.MatchedRoles(req, currentUser)

	file := filebox.AccessFile(filePath, matchedRoles...)
	if reader, err := file.Read(); err == nil {
		fileName := filepath.Base(file.FilePath)

		w.Header().Set("Content-Disposition", "attachment; filename="+fileName)
		w.Header().Set("Content-Type", req.Header.Get("Content-Type"))
		http.ServeContent(w, req, fileName, time.Now(), reader)
	} else if err == roles.ErrPermissionDenied && filebox.Auth != nil {
		http.Redirect(w, req, filebox.Auth.LoginURL(context), http.StatusFound)
	} else {
		http.NotFound(w, req)
	}
}
