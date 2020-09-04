package filebox

import (
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/ecletus/auth"
	"github.com/ecletus/common"
	"github.com/ecletus/roles"
)

// Download is a handler will return a specific file
func (filebox *Filebox) Download(w http.ResponseWriter, req *http.Request) {
	var (
		currentUser common.User
		filePath    = strings.TrimPrefix(req.URL.Path, filebox.Router.Prefix())
		context     = filebox.Admin.NewContext(w, w)
	)

	if Auth := filebox.Auth; Auth != nil {
		var err error
		if currentUser, err = Auth.GetCurrentUser(context); err != nil {
			if err == auth.ErrNoSession {
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	matchedRoles := roles.MatchedRoles(req, currentUser)

	file := filebox.AccessFile(filePath, matchedRoles.Strings()...)
	if reader, err := file.Read(context); err == nil {
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
