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

	router.Use(setUserStatus())
	router.GET("/", showIndexPage)
	router.POST("/", showIndexPageWithFilter)

	userRoutes := router.Group("/u")
	{
		userRoutes.GET("/login", ensureNotLoggedIn(), showLoginPage)
		userRoutes.POST("/login", ensureNotLoggedIn(), performLogin)
		userRoutes.GET("/logout", ensureLoggedIn(), logout)
		userRoutes.GET("/register", ensureNotLoggedIn(), showRegistrationPage)
		userRoutes.POST("/register", ensureNotLoggedIn(), register)
		userRoutes.GET("/profile", ensureLoggedIn(), showProfilePage)
		userRoutes.POST("/profile", ensureLoggedIn(), changeData)
	}
	productRoutes := router.Group("/product")
	{
		productRoutes.GET("/view/:product_id", getProduct)
		productRoutes.GET("/createProduct",ensureLoggedIn(),showAddProductPage)
		productRoutes.POST("/createProduct",ensureLoggedIn(),AddProductPage)
	}
}
func AddProductPage(c *gin.Context)  {

	productName := c.PostForm("productName")
	productCalories,err:=strconv.ParseFloat(c.PostForm("productCalories"),3)
	is:=isNotExistProduct(productName)
	if err != nil || is!=true {
		c.JSON(200,gin.H{
			"message":"Продукт або страва з таким іменем уже існує",
		})
		panic(err)
	}else{
		AddProduct(productName,productCalories)
		c.JSON(200,gin.H{
			"message":"Успішно додано",
		})
	}
}
func AddProduct(productName string,productCalories float64)  {
	session, err := mgo.Dial("mongodb://127.0.0.1")
	if err != nil {
		panic(err)
	}
	defer session.Close()
	productCollection := session.DB("CalorieCountingSystem").C("Products")
	p:=&product{
		ID: bson.NewObjectId(),
		Name: productName,
		Calories: productCalories,
	}
	productsList=append(productsList, *p)
	err = productCollection.Insert(p)
	if err != nil {
		fmt.Println(err)
	}
}
func isNotExistProduct(productName string) bool {
	session, err := mgo.Dial("mongodb://127.0.0.1")
	if err != nil {
		panic(err)
	}
	defer session.Close()
	var products=[]product{}
	productCollection := session.DB("CalorieCountingSystem").C("Products")
	productCollection.Find(bson.M{"name": productName}).All(&products)
	if(len(products)>0){
		return false
	}
	return true

}
func showAddProductPage(c *gin.Context)  {
	render(c, gin.H{
		"title": "AddProduct",
	}, "add-product.html")
}
func showIndexPage(c *gin.Context) {
	products := getAllProducts()

	render(c, gin.H{
		"title":   "Home Page",
		"payload": products}, "index.html")
}
func showIndexPageWithFilter(c *gin.Context) {
	products := getFilterProducts(c)
	/*if c.Bind(&products) != nil {
		return
	}
	// Call the render function with the name of the template to render
	c.JSON(200,products)*/
	if(len(products)==0) {
		c.HTML(http.StatusBadRequest, "index.html", gin.H{
			"ErrorTitle":   "Упс...",
			"ErrorMessage": "За вашим запитом нічого не знайдено"})
	} else{
		render(c, gin.H{
			"title":   "Home Page",
			"payload": products}, "index.html")
	}

}
func showProfilePage(c *gin.Context) {
	//fmt.Println(LogUser.Name)
	render(c, gin.H{
		"title": "Profile","payload": LogUser}, "profile.html")
}
func getFilterProducts(c *gin.Context) []product {

	name := c.PostForm("product")
	//fmt.Println(name)
	var p =[]product{}
	for _,a := range productsList{
		if(strings.Contains(strings.ToLower(a.Name),strings.ToLower(name))) {
			p = append(p, a)
		}
	}
	return p
}
func getProduct(c *gin.Context) {

	if c.Param("product_id")!="" {
		//fmt.Println(c.Param("product_id"))
		if product, err := getProductByID(c.Param("product_id")); err == nil {
			// template
			render(c, gin.H{
				"title":   product.Name,
				"payload": product}, "product.html")

		} else {

			c.AbortWithError(http.StatusNotFound, err)
		}

	} else {
		c.AbortWithStatus(http.StatusNotFound)
	}
}

func changeData(c *gin.Context) {

	login := c.PostForm("login")
	password := c.PostForm("password")
	name:=c.PostForm("name")
	sex:=c.PostForm("sex")
	height,err:=strconv.ParseFloat(c.PostForm("height"),3)
	weight,err:=strconv.ParseFloat(c.PostForm("weight"),3)
	age,err:=strconv.ParseInt(c.PostForm("age"),10,64)
	isOk:=updateUser(login,password,name,sex,height,weight,age)
	if err != nil ||isOk!=true {
		c.JSON(200,gin.H{
			"message":"Дані не змінено.",
		})
		panic(err)
	}else{
		c.JSON(200,gin.H{
			"message":"Дані успішно змінено.",
		})
	}
	//fmt.Println(login,password,name,sex,height,weight,age)



	/*if a, err := createNewArticle(title, content); err == nil {
		render(c, gin.H{
			"title":   "Submission Successful",
			"payload": a}, "submission-successful.html")
	} else {

		c.AbortWithStatus(http.StatusBadRequest)
	}*/
}
func showLoginPage(c *gin.Context) {

	render(c, gin.H{
		"title": "Login",
	}, "login.html")
}


func performLogin(c *gin.Context) {

	login := c.PostForm("login")
	password := c.PostForm("password")
	//fmt.Println(login,password)
	//var sameSiteCookie http.SameSite;
	if isUserValid(login, password) {
		token := generateSessionToken()
		c.SetCookie("token", token, 3600, "", "", false, true)
		//func (c *Context) SetCookie(name string, value string, maxAge int, path string, domain string, secure bool, httpOnly bool
		c.Set("is_logged_in", true)

		render(c, gin.H{
			"title": "Successful Login"}, "login-successful.html")

	} else {
		c.HTML(http.StatusBadRequest, "login.html", gin.H{
			"ErrorTitle":   "Login Failed",
			"ErrorMessage": "Invalid credentials provided"})
	}
}

func generateSessionToken() string {
	return strconv.FormatInt(rand.Int63(), 16)
}



func showRegistrationPage(c *gin.Context) {
	render(c, gin.H{
		"title": "Register"}, "register.html")
}

func register(c *gin.Context) {

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

		token := generateSessionToken()
		c.SetCookie("token", token, 3600, "", "", false, true)
		c.Set("is_logged_in", true)

		render(c, gin.H{
			"title": "Successful registration & Login"}, "login-successful.html")

	} else {

		c.HTML(http.StatusBadRequest, "register.html", gin.H{
			"ErrorTitle":   "Registration Failed",
			"ErrorMessage": err.Error()})

	}
}
func ensureLoggedIn() gin.HandlerFunc {
	return func(c *gin.Context) {
		loggedInInterface, _ := c.Get("is_logged_in")
		loggedIn := loggedInInterface.(bool)
		if !loggedIn {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	}
}

func ensureNotLoggedIn() gin.HandlerFunc {
	return func(c *gin.Context) {
		loggedInInterface, _ := c.Get("is_logged_in")
		loggedIn := loggedInInterface.(bool)
		if loggedIn {
			if token, err := c.Cookie("token"); err == nil || token != "" {
				c.AbortWithStatus(http.StatusUnauthorized)
			}

		}
	}
}


func setUserStatus() gin.HandlerFunc {
	return func(c *gin.Context) {
		if token, err := c.Cookie("token"); err == nil || token != "" {
			c.Set("is_logged_in", true)
		} else {
			c.Set("is_logged_in", false)
		}
	}
}


type product struct {
	ID bson.ObjectId `bson:"_id"`
	Name string `bson:"name"`
	Calories float64 `bson:"calories"`
}


var productsList = []product{}



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


func getProductByID(id string) (*product, error) {
	for _, a := range productsList {
		//fmt.Println(a.ID.String())
		if "ObjectIdHex(\""+a.ID.Hex()+"\")" == id {
			return &a, nil
		}
	}
	return nil, errors.New("Product  not found")
}


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
var LogUser person
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
			LogUser=result[i];
			//fmt.Println(LogUser.Name)
			//println("is valid")
			return true
		}
	}
	return false

}
func updateUser(login, password,name,sex string,weight,height float64,age int64) bool {
	session, err := mgo.Dial("mongodb://127.0.0.1")
	if err != nil {
		panic(err)
	}

	defer session.Close()
	usersCollection := session.DB("CalorieCountingSystem").C("Users")
	LogUser.Name=name
	LogUser.Password=password
	LogUser.Age=age
	LogUser.Height=height
	LogUser.Weight=weight
	LogUser.Sex=sex
	err = usersCollection.Update(bson.M{"login": login}, bson.M{"$set":bson.M{"password": password, "name": name, "sex": sex,  "height": height, "weight": weight, "age": age }})
	if err != nil {
		panic(err)
		return false
	}
	//fmt.Println(len(result))
	return true

}


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
	LogUser=*p;
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

}


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
	c.SetCookie("token", "", -1, "", "", false, true)
	c.Redirect(http.StatusTemporaryRedirect, "/")
}

func main() {
	gin.SetMode(gin.ReleaseMode)
	router = gin.Default()
	router.LoadHTMLGlob("D:\\Go\\HW12\\templates/*")
	initializeRoutes()
	router.Run()
}


