// main.go

package main

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
)
// router
var router *gin.Engine
func initializeRoutes() {

	// Use the setUserStatus middleware for every route to set a flag
	// indicating whether the request was from an authenticated user or not
	router.Use(setUserStatus())

	// Handle the index route
	router.GET("/", showIndexPage)
	router.POST("/", showIndexPageWithFilter)

	// Group user related routes together
	userRoutes := router.Group("/u")
	{
		// Handle the GET requests at /u/login
		// Show the login page
		// Ensure that the user is not logged in by using the middleware
		userRoutes.GET("/login", ensureNotLoggedIn(), showLoginPage)

		// Handle POST requests at /u/login
		// Ensure that the user is not logged in by using the middleware
		userRoutes.POST("/login", ensureNotLoggedIn(), performLogin)

		// Handle GET requests at /u/logout
		// Ensure that the user is logged in by using the middleware
		userRoutes.GET("/logout", ensureLoggedIn(), logout)

		// Handle the GET requests at /u/register
		// Show the registration page
		// Ensure that the user is not logged in by using the middleware
		userRoutes.GET("/register", ensureNotLoggedIn(), showRegistrationPage)

		// Handle POST requests at /u/register
		// Ensure that the user is not logged in by using the middleware
		userRoutes.POST("/register", ensureNotLoggedIn(), register)
	}

	// Group article related routes together
	articleRoutes := router.Group("/product")
	{
		// Handle GET requests at /article/view/some_article_id
		articleRoutes.GET("/view/:product_id", getProduct)

		// Handle the GET requests at /article/create
		// Show the article creation page
		// Ensure that the user is logged in by using the middleware
		articleRoutes.GET("/create", ensureLoggedIn(), showArticleCreationPage)

		// Handle POST requests at /article/create
		// Ensure that the user is logged in by using the middleware
		articleRoutes.POST("/create", ensureLoggedIn(), createArticle)
	}
}
func showIndexPage(c *gin.Context) {
	products := getAllProducts()

	// Call the render function with the name of the template to render
	render(c, gin.H{
		"title":   "Home Page",
		"payload": products}, "index.html")
}
func showIndexPageWithFilter(c *gin.Context) {
	products := getFilterProducts(c)

	// Call the render function with the name of the template to render
	render(c, gin.H{
		"title":   "Home Page",
		"payload": products}, "index.html")
}
func showArticleCreationPage(c *gin.Context) {
	// Call the render function with the name of the template to render
	render(c, gin.H{
		"title": "Create New Article"}, "create-article.html")
}
func getFilterProducts(c *gin.Context) []product {
	name := c.PostForm("product")
	fmt.Println(name)
	var p =[]product{}
	for _,a := range productsList{
		if(strings.Contains(strings.ToLower(a.Name),strings.ToLower(name))) {
			p = append(p, a)
		}
	}
	return p
}
func getProduct(c *gin.Context) {
	// Check if the article ID is valid
	if c.Param("product_id")!="" {
		// Check if the article exists
		fmt.Println(c.Param("product_id"))
		if product, err := getProductByID(c.Param("product_id")); err == nil {
			// Call the render function with the title, article and the name of the
			// template
			render(c, gin.H{
				"title":   product.Name,
				"payload": product}, "article.html")

		} else {
			// If the article is not found, abort with an error
			c.AbortWithError(http.StatusNotFound, err)
		}

	} else {
		// If an invalid article ID is specified in the URL, abort with an error
		c.AbortWithStatus(http.StatusNotFound)
	}
}

func createArticle(c *gin.Context) {
	// Obtain the POSTed title and content values
	title := c.PostForm("title")
	content := c.PostForm("content")

	if a, err := createNewArticle(title, content); err == nil {
		// If the article is created successfully, show success message
		render(c, gin.H{
			"title":   "Submission Successful",
			"payload": a}, "submission-successful.html")
	} else {
		// if there was an error while creating the article, abort with an error
		c.AbortWithStatus(http.StatusBadRequest)
	}
}
func showLoginPage(c *gin.Context) {
	// Call the render function with the name of the template to render
	render(c, gin.H{
		"title": "Login",
	}, "login.html")
}


func performLogin(c *gin.Context) {
	// Obtain the POSTed login and password values
	login := c.PostForm("login")
	password := c.PostForm("password")
	//fmt.Println(login,password)
	//var sameSiteCookie http.SameSite;

	// Check if the login/password combination is valid
	if isUserValid(login, password) {
		// If the login/password is valid set the token in a cookie
		token := generateSessionToken()
		c.SetCookie("token", token, 3600, "", "", false, true)
		//func (c *Context) SetCookie(name string, value string, maxAge int, path string, domain string, secure bool, httpOnly bool
		c.Set("is_logged_in", true)

		render(c, gin.H{
			"title": "Successful Login"}, "login-successful.html")

	} else {
		// If the login/password combination is invalid,
		// show the error message on the login page
		c.HTML(http.StatusBadRequest, "login.html", gin.H{
			"ErrorTitle":   "Login Failed",
			"ErrorMessage": "Invalid credentials provided"})
	}
}

func generateSessionToken() string {
	// We're using a random 16 character string as the session token
	// This is NOT a secure way of generating session tokens
	// DO NOT USE THIS IN PRODUCTION
	return strconv.FormatInt(rand.Int63(), 16)
}



func showRegistrationPage(c *gin.Context) {
	// Call the render function with the name of the template to render
	render(c, gin.H{
		"title": "Register"}, "register.html")
}

func register(c *gin.Context) {
	// Obtain the POSTed login and password values
	login := c.PostForm("login")
	password := c.PostForm("password")
	name:=c.PostForm("name")
	sex:=c.PostForm("sex")
	height,err:=strconv.ParseFloat(c.PostForm("height"),3)
	weight,err:=strconv.ParseFloat(c.PostForm("weight"),3)
	age,err:=strconv.ParseInt(c.PostForm("age"),10,64)
	if err != nil {
		panic(err)
	}

	//var sameSiteCookie http.SameSite;

	if _, err := registerNewUser(login, password,name,sex,weight,height,age); err == nil {
		// If the user is created, set the token in a cookie and log the user in
		token := generateSessionToken()
		c.SetCookie("token", token, 3600, "", "", false, true)
		c.Set("is_logged_in", true)

		render(c, gin.H{
			"title": "Successful registration & Login"}, "login-successful.html")

	} else {
		// If the login/password combination is invalid,
		// show the error message on the login page
		c.HTML(http.StatusBadRequest, "register.html", gin.H{
			"ErrorTitle":   "Registration Failed",
			"ErrorMessage": err.Error()})

	}
}
func ensureLoggedIn() gin.HandlerFunc {
	return func(c *gin.Context) {
		// If there's an error or if the token is empty
		// the user is not logged in
		loggedInInterface, _ := c.Get("is_logged_in")
		loggedIn := loggedInInterface.(bool)
		if !loggedIn {
			//if token, err := c.Cookie("token"); err != nil || token == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	}
}

// This middleware ensures that a request will be aborted with an error
// if the user is already logged in
func ensureNotLoggedIn() gin.HandlerFunc {
	return func(c *gin.Context) {
		// If there's no error or if the token is not empty
		// the user is already logged in
		loggedInInterface, _ := c.Get("is_logged_in")
		loggedIn := loggedInInterface.(bool)
		if loggedIn {
			if token, err := c.Cookie("token"); err == nil || token != "" {
				c.AbortWithStatus(http.StatusUnauthorized)
			}

		}
	}
}

// This middleware sets whether the user is logged in or not
func setUserStatus() gin.HandlerFunc {
	return func(c *gin.Context) {
		if token, err := c.Cookie("token"); err == nil || token != "" {
			c.Set("is_logged_in", true)
		} else {
			c.Set("is_logged_in", false)
		}
	}
}


type article struct {
	ID      int    `json:"id"`
	Title   string `json:"title"`
	Content string `json:"content"`
}
type product struct {
	ID bson.ObjectId `bson:"_id"`
	Name string `bson:"name"`
	Calories float64 `bson:"calories"`
}

// For this demo, we're storing the article list in memory
// In a real application, this list will most likely be fetched
// from a database or from static files
var productsList = []product{}
/*var productsList = []article{
	article{ID: 1, Title: "Article 1", Content: "Article 1 body"},
	article{ID: 2, Title: "Article 2", Content: "Article 2 body"},
	article{ID: 3, Title: "Article 3", Content: "Article 3 body"},
}*/

// Return a list of all the products
func getAllProducts() []product {
	productsList=[]product{}
	session, err := mgo.Dial("mongodb://127.0.0.1")
	if err != nil {
		panic(err)
	}
	defer session.Close()
	usersCollection := session.DB("CalorieCountingSystem").C("Products")
	//var result = [] person {}
	usersCollection.Find(nil).All(&productsList)
	return productsList
}

// Fetch an article based on the ID supplied
func getProductByID(id string) (*product, error) {
	for _, a := range productsList {
		//fmt.Println(a.ID.String())
		if "ObjectIdHex(\""+a.ID.Hex()+"\")" == id {
			return &a, nil
		}
	}
	return nil, errors.New("Product  not found")
}

// Create a new article with the title and content provided
func createNewArticle(title, content string) (*article, error) {
	// Set the ID of a new article to one more than the number of articles
	a := article{ID: len(productsList) + 1, Title: title, Content: content}

	// Add the article to the list of articles
	//productsList = append(productsList, a)

	return &a, nil
}

//user

/*type user struct {
	Username string `json:"username"`
	Password string `json:"-"`
}*/
type person struct{
	//Id bson.ObjectId `bson:"_id"`
	Login string `bson:"login"`
	Password string `bson:"password"`
	Name string `bson:"name"`
	Sex string `bson:"sex"`
	Height float64 `bson:"height"`
	Weight float64 `bson:"weigth"`
	Age int64 `bson:"age"`
}

// For this demo, we're storing the user list in memory
// We also have some users predefined.
// In a real application, this list will most likely be fetched
// from a database. Moreover, in production settings, you should
// store passwords securely by salting and hashing them instead
// of using them as we're doing in this demo
/*var userList = []user{
	user{Username: "user1", Password: "pass1"},
	user{Username: "user2", Password: "pass2"},
	user{Username: "user3", Password: "pass3"},
}*/

// Check if the login and password combination is valid
func isUserValid(login, password string) bool {
	session, err := mgo.Dial("mongodb://127.0.0.1")
	if err != nil {
		panic(err)
	}
	//fmt.Println(login,password)
	defer session.Close()
	usersCollection := session.DB("CalorieCountingSystem").C("Users")
	var result = [] person {}
	usersCollection.Find(bson.M{"login": login}).All(&result)
	//fmt.Println(len(result))
	for i:=0;i< len(result);i++{
		//fmt.Println(result[i].Login,result[i].Password)
		//fmt.Println(result[i].Login,login,result[i].Password,password)
		if result[i].Login==login&&result[i].Password==password   {
			//println("is valid")
			return true
		}
	}
	return false
	/*
	for _, u := range userList {
		if u.Username == username && u.Password == password {
			return true
		}
	}
	return false*/
}

// Register a new user with the given login and password
//registerNewUser(login, password,name,sex,weight,height,age)
func registerNewUser(login, password,name,sex string,weight,height float64,age int64) (*person, error) {
	if strings.TrimSpace(password) == "" {
		return nil, errors.New("The password can't be empty")
	} else if !isUsernameAvailable(login) {
		return nil, errors.New("The login isn't available")
	}
	session, err := mgo.Dial("mongodb://127.0.0.1")
	if err != nil {
		panic(err)
	}
	//println("Connection...")
	defer session.Close()
	usersCollection := session.DB("CalorieCountingSystem").C("Users")
	p:=&person{
		Login: login,
		Password: password,
		Name: name,
		Sex: sex,
		Height: height,
		Weight: weight,
		Age: age  }
	err = usersCollection.Insert(p)
	if err != nil {
		fmt.Println(err)
	}
	/*
	u := user{Username: username, Password: password}

	userList = append(userList, u)*/

	return p, nil
}

// Check if the supplied username is available
func isUsernameAvailable(login string) bool {
	session, err := mgo.Dial("mongodb://127.0.0.1")
	if err != nil {
		panic(err)
	}
	//println("Connection...")
	defer session.Close()
	usersCollection := session.DB("CalorieCountingSystem").C("Users")
	var result = []person {}
	usersCollection.Find(bson.M{"login": login}).All(&result)
	for i:=0;i< len(result);i++ {
		if  result[i].Login==login{
			return false
		}
	}
	return true

	/*for _, u := range userList {
		if u.Username == username {
			return false
		}
	}
	return true*/
}

// Render one of HTML, JSON or CSV based on the 'Accept' header of the request
// If the header doesn't specify this, HTML is rendered, provided that
// the template name is present
func render(c *gin.Context, data gin.H, templateName string) {
	loggedInInterface, _ := c.Get("is_logged_in")
	data["is_logged_in"] = loggedInInterface.(bool)
	switch c.Request.Header.Get("Accept") {
	case "application/json":
		// Respond with JSON
		c.JSON(http.StatusOK, data["payload"])
	case "application/xml":
		// Respond with XML
		c.XML(http.StatusOK, data["payload"])
	default:
		// Respond with HTML
		c.HTML(http.StatusOK, templateName, data)
	}
}
func logout(c *gin.Context) {

	//var sameSiteCookie http.SameSite;

	// Clear the cookie
	c.SetCookie("token", "", -1, "", "", false, true)
	//SetCookie(name string, value string, maxAge int, path string, domain string, secure bool, httpOnly bool)
	// Redirect to the home page
	c.Redirect(http.StatusTemporaryRedirect, "/")
}

func main() {
	// Set Gin to production mode
	gin.SetMode(gin.ReleaseMode)

	// Set the router as the default one provided by Gin
	router = gin.Default()

	// Process the templates at the start so that they don't have to be loaded
	// from the disk again. This makes serving HTML pages very fast.
	router.LoadHTMLGlob("D:\\Go\\HW12\\templates/*")

	// Initialize the routes
	initializeRoutes()

	// Start serving the application
	router.Run()
}


