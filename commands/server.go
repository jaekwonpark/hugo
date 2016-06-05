// Copyright 2016 The Hugo Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package commands

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/spf13/hugo/helpers"
	"github.com/spf13/hugo/hugofs"
	jww "github.com/spf13/jwalterweatherman"
	"github.com/spf13/viper"
	"mime"
	"io"
	"html/template"
	"io/ioutil"
	"crypto/sha1"
	"bytes"
	"encoding/base64"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
)

var (
	disableLiveReload bool
	renderToDisk      bool
	serverAppend      bool
	serverInterface   string
	serverPort        int
	serverWatch       bool
)

const loginTemplate = `
  <head>
    <title>Parkha.net</title>
  </head>
  <body>
    <div class="container">
      <br>
      <form action="{{.Dest}}" method="post">
         <input type="password" placeholder="" name="password" value="">
        <input class="btn btn-default" type="submit" value="Auth">
      </form>
    </div>
  </body>
  </html>
`
const changePwTemplate = `
  <head>
    <title>Parkha.net</title>
  </head>
  <body>
    <div class="container">
      <br>
      <form action="{{.Dest}}" method="post">
         <input type="password" placeholder="" name="password" value="">
        <input class="btn btn-default" type="submit" value="Change">
      </form>
    </div>
  </body>
  </html>
`

//var serverCmdV *cobra.Command

var serverCmd = &cobra.Command{
	Use:     "server",
	Aliases: []string{"serve"},
	Short:   "A high performance webserver",
	Long: `Hugo provides its own webserver which builds and serves the site.
While hugo server is high performance, it is a webserver with limited options.
Many run it in production, but the standard behavior is for people to use it
in development and use a more full featured server such as Nginx or Caddy.

'hugo server' will avoid writing the rendered and served content to disk,
preferring to store it in memory.

By default hugo will also watch your files for any changes you make and
automatically rebuild the site. It will then live reload any open browser pages
and push the latest content to them. As most Hugo sites are built in a fraction
of a second, you will be able to save and see your changes nearly instantly.`,
	//RunE: server,
}

type filesOnlyFs struct {
	fs http.FileSystem
}

type noDirFile struct {
	http.File
}

func (fs filesOnlyFs) Open(name string) (http.File, error) {
	f, err := fs.fs.Open(name)
	if err != nil {
		return nil, err
	}
	return noDirFile{f}, nil
}

func (f noDirFile) Readdir(count int) ([]os.FileInfo, error) {
	return nil, nil
}

func init() {
	initHugoBuilderFlags(serverCmd)

	serverCmd.Flags().IntVarP(&serverPort, "port", "p", 1313, "port on which the server will listen")
	serverCmd.Flags().StringVarP(&serverInterface, "bind", "", "127.0.0.1", "interface to which the server will bind")
	serverCmd.Flags().BoolVarP(&serverWatch, "watch", "w", true, "watch filesystem for changes and recreate as needed")
	serverCmd.Flags().BoolVarP(&serverAppend, "appendPort", "", true, "append port to baseurl")
	serverCmd.Flags().BoolVar(&disableLiveReload, "disableLiveReload", false, "watch without enabling live browser reload on rebuild")
	serverCmd.Flags().BoolVar(&renderToDisk, "renderToDisk", false, "render to Destination path (default is render to memory & serve from there)")
	serverCmd.Flags().String("memstats", "", "log memory usage to this file")
	serverCmd.Flags().Int("meminterval", 100, "interval to poll memory usage (requires --memstats)")
	serverCmd.RunE = server

	mime.AddExtensionType(".json", "application/json; charset=utf8")
}

func server(cmd *cobra.Command, args []string) error {
	if err := InitializeConfig(serverCmd); err != nil {
		return err
	}

	if flagChanged(cmd.Flags(), "disableLiveReload") {
		viper.Set("DisableLiveReload", disableLiveReload)
	}

	if serverWatch {
		viper.Set("Watch", true)
	}

	if viper.GetBool("watch") {
		serverWatch = true
		watchConfig()
	}

	l, err := net.Listen("tcp", net.JoinHostPort(serverInterface, strconv.Itoa(serverPort)))
	if err == nil {
		l.Close()
	} else {
		if flagChanged(serverCmd.Flags(), "port") {
			// port set explicitly by user -- he/she probably meant it!
			return newSystemErrorF("Port %d already in use", serverPort)
		}
		jww.ERROR.Println("port", serverPort, "already in use, attempting to use an available port")
		sp, err := helpers.FindAvailablePort()
		if err != nil {
			return newSystemError("Unable to find alternative port to use:", err)
		}
		serverPort = sp.Port
	}

	viper.Set("port", serverPort)

	BaseURL, err := fixURL(baseURL)
	if err != nil {
		return err
	}
	viper.Set("BaseURL", BaseURL)

	// Read PW file
	hashedPw, err := ioutil.ReadFile(CredFile)
	if err != nil || len(hashedPw) < 1 {
		viper.Set("HashedPw", "")
	} else {
		viper.Set("HashedPw", hashedPw)
	}

	// Read and set Key
	key, err := ioutil.ReadFile(KeyFile)
	key = key[:32]
	if err != nil || len(key) < 1 {
		return fmt.Errorf("Can not read cipher key file or the file is empty")
	}
	viper.Set("Key", string(key))

	if err := memStats(); err != nil {
		jww.ERROR.Println("memstats error:", err)
	}

	// If a Destination is provided via flag write to disk
	if destination != "" {
		renderToDisk = true
	}

	// Hugo writes the output to memory instead of the disk
	if !renderToDisk {
		hugofs.SetDestination(new(afero.MemMapFs))
		// Rendering to memoryFS, publish to Root regardless of publishDir.
		viper.Set("PublishDir", "/")
	}

	if err := build(serverWatch); err != nil {
		return err
	}

	// Watch runs its own server as part of the routine
	if serverWatch {
		watchDirs := getDirList()
		baseWatchDir := viper.GetString("WorkingDir")
		for i, dir := range watchDirs {
			watchDirs[i], _ = helpers.GetRelativePath(dir, baseWatchDir)
		}

		rootWatchDirs := strings.Join(helpers.UniqueStrings(helpers.ExtractRootPaths(watchDirs)), ",")

		jww.FEEDBACK.Printf("Watching for changes in %s%s{%s}\n", baseWatchDir, helpers.FilePathSeparator, rootWatchDirs)
		err := NewWatcher(serverPort)

		if err != nil {
			return err
		}
	}

	serve(serverPort)

	return nil
}

func serve(port int) {
	if renderToDisk {
		jww.FEEDBACK.Println("Serving pages from " + helpers.AbsPathify(viper.GetString("PublishDir")))
	} else {
		jww.FEEDBACK.Println("Serving pages from memory")
	}

	httpFs := afero.NewHttpFs(hugofs.Destination())
	fs := filesOnlyFs{httpFs.Dir(helpers.AbsPathify(viper.GetString("PublishDir")))}
	fmt.Printf("publishDir:%s\n",viper.GetString("PublishDir"))
	fmt.Printf("dest:%s\n",hugofs.Destination().Name())
	fileserver := http.FileServer(fs)

	// We're only interested in the path
	u, err := url.Parse(viper.GetString("BaseURL"))
	if err != nil {
		jww.ERROR.Fatalf("Invalid BaseURL: %s", err)
	}
	if u.Path == "" || u.Path == "/" {
		fmt.Printf("1 register path:%s\n", u.Path)
		http.Handle("/", SessionFileServer(fs, fileserver))
	} else {
		fmt.Printf("2 register path:%s\n", u.Path)
		http.Handle(u.Path, http.StripPrefix(u.Path, SessionFileServer(fs, fileserver)))
	}

	http.HandleFunc(PRIVATE, tslHandler)

	//u.Scheme = "http"
	jww.FEEDBACK.Printf("Web Server is available at %s (bind address %s)\n", u.String(), serverInterface)
	fmt.Println("Press Ctrl+C to stop")


	go func() {
		err = http.ListenAndServeTLS(":443", "/home/jkpark/Cert/parkha.net.pem", "/home/jkpark/Cert/parkha.net.key", nil)
		if err != nil {
			jww.ERROR.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
	}()

	endpoint := net.JoinHostPort(serverInterface, strconv.Itoa(port))
	err = http.ListenAndServe(endpoint, nil)
	if err != nil {
		jww.ERROR.Printf("Error: %s\n", err.Error())
		os.Exit(1)
	}
}

func SessionFileServer(fs http.FileSystem, handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("File:%s\n", fs)
		handler.ServeHTTP(w, r)
	})
}

const (
	PRIVATE = "/prvt/"
	HOME = "http://parkha.net:8090"
	SESSION_COOKIE = "auth"
)

func tslHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("tslHandler, path:%s\n", r.URL.Path)
	hashedPw := viper.GetString("HashedPw")
	fmt.Printf("hashedPw=%#v\n", hashedPw)
	if hashedPw == "" { // Create a new password
		if r.URL.Path == "/prvt/pwreset" {
			fmt.Printf("I'm in pwreset\n")
			newPw := r.FormValue("password")
			fmt.Printf("pwNew:%s\n", newPw)
			hashed := genHash(newPw)
			fmt.Printf("hashed:%#v\n", hashed)
			err := ioutil.WriteFile(CredFile, hashed, 0600)
			if err != nil {
				panic(err)
			}
			viper.Set("HashedPw", string(hashed))
			fmt.Printf("viper HashedPw:%s\n",viper.GetString("HashedPw"))
			setCookie(w, hashed)
			http.Redirect(w, r, PRIVATE, 301)
		} else {
			vars := map[string]interface{}{
				"Dest":       "/prvt/pwreset",
			}
			tmpl, err := template.New("template").Parse(changePwTemplate)
			if err != nil {
				io.WriteString(w, "template failure")
			} else {
				err = tmpl.Execute(w, vars)
			}
		}
	} else if r.URL.Path == "/prvt/login" {
		if verifyCookie(r) {
			http.Redirect(w, r, HOME, 301)
		}
		fmt.Printf("Show login\n")
		vars := map[string]interface{}{
			"Dest":       "/prvt/auth?.done="+url.QueryEscape(r.URL.Path),
		}

		tmpl, err := template.New("template").Parse(loginTemplate)
		if err != nil {
			io.WriteString(w, "template failure")
		} else {
			err = tmpl.Execute(w, vars)

		}
	} else if r.URL.Path == "/prvt/auth" {
		h := sha1.New()
		h.Write([]byte(r.FormValue("password")))
		bs := h.Sum(nil)
		fmt.Printf("bs:%#v\nhasedPw:%#v\n",bs, viper.GetString("HashedPw"))
		if bytes.Equal(bs, []byte(viper.GetString("HashedPw"))) {
			setCookie(w, bs)
			http.Redirect(w, r, HOME, 301)
		} else {
			io.WriteString(w, "Wrong")
		}
	} else if verifyCookie(r) {
		io.WriteString(w, "Welcome to "+r.URL.Path)
	} else {
		io.WriteString(w, "Not authorized to view "+r.URL.Path)
	}

}

func setCookie(w http.ResponseWriter, hashed []byte) {
	expiration := time.Now().Add(1*time.Minute)
	signedCookie := sign(expiration)

	fmt.Printf("signedCooke:%s\n", signedCookie)

	cookie := http.Cookie{Name: SESSION_COOKIE,Value:signedCookie,Expires:expiration}
	http.SetCookie(w, &cookie)
}

func genHash(str string) []byte {
	h := sha1.New()
	h.Write([]byte(str))
	return h.Sum(nil)
}

func sign(expiresAt time.Time) string {

	key := viper.GetString("Key")
	payload := fmt.Sprintf("%s^%d", key, expiresAt.Unix())
	signature, err := encrypt(key, payload)
	if err != nil {
		panic(fmt.Errorf("Failed in encrypt:%s", err))
	}

	return signature
}

func encrypt(key, text string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(text))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(text))

	signature := base64.StdEncoding.EncodeToString(ciphertext)
	return signature, nil
}

func decrypt(key, text string) (string, error) {

	data, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	if len(data) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := data[:aes.BlockSize]
	text2 := data[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text2, text2)

	return string(text2), nil
}

func verifyCookie(r *http.Request) bool {
	authCookie, _ := r.Cookie(SESSION_COOKIE)
	fmt.Printf("authCookie:%s\n", authCookie)
	if authCookie == nil || authCookie.Value == "" {
		return false
	}
	key := viper.GetString("Key")
	fmt.Printf("key=%v\n", key)
	decrypted, err := decrypt(key, authCookie.Value)
	if err != nil {
		return false
	}
	fmt.Printf("decrypted=%s\n", decrypted)
	parts := strings.Split(decrypted, "^")
	if len(parts) != 2 || parts[0] != key || isExpired(parts[1]) {
		return false
	}

	fmt.Printf("decrypted key=%s\n", parts[0])
	fmt.Printf("decrypted time=%s\n", parts[1])

	return true

}

func isExpired(timestamp string) bool {
	i, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	tm := time.Unix(i, 0)
	now := time.Now()
	return tm.Unix() < now.Unix()
}

// fixURL massages the BaseURL into a form needed for serving
// all pages correctly.
func fixURL(s string) (string, error) {
	useLocalhost := false
	if s == "" {
		s = viper.GetString("BaseURL")
		useLocalhost = true
	}
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		s = "http://" + s
	}
	if !strings.HasSuffix(s, "/") {
		s = s + "/"
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", err
	}

	if serverAppend {
		if useLocalhost {
			u.Host = fmt.Sprintf("localhost:%d", serverPort)
			u.Scheme = "http"
			return u.String(), nil
		}
		host := u.Host
		if strings.Contains(host, ":") {
			host, _, err = net.SplitHostPort(u.Host)
			if err != nil {
				return "", fmt.Errorf("Failed to split BaseURL hostpost: %s", err)
			}
		}
		u.Host = fmt.Sprintf("%s:%d", host, serverPort)
		return u.String(), nil
	}

	if useLocalhost {
		u.Host = "localhost"
	}
	return u.String(), nil
}

func memStats() error {
	memstats := serverCmd.Flags().Lookup("memstats").Value.String()
	if memstats != "" {
		interval, err := time.ParseDuration(serverCmd.Flags().Lookup("meminterval").Value.String())
		if err != nil {
			interval, _ = time.ParseDuration("100ms")
		}

		fileMemStats, err := os.Create(memstats)
		if err != nil {
			return err
		}

		fileMemStats.WriteString("# Time\tHeapSys\tHeapAlloc\tHeapIdle\tHeapReleased\n")

		go func() {
			var stats runtime.MemStats

			start := time.Now().UnixNano()

			for {
				runtime.ReadMemStats(&stats)
				if fileMemStats != nil {
					fileMemStats.WriteString(fmt.Sprintf("%d\t%d\t%d\t%d\t%d\n",
						(time.Now().UnixNano()-start)/1000000, stats.HeapSys, stats.HeapAlloc, stats.HeapIdle, stats.HeapReleased))
					time.Sleep(interval)
				} else {
					break
				}
			}
		}()
	}
	return nil
}
