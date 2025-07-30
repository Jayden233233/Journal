# Go + Gin + GORM 个人博客系统后端实现

下面是一个完整的个人博客系统后端实现，包含用户认证、文章管理和评论功能。

## 1. 项目结构

```
blog-backend/
├── config/
│   └── config.go
├── controllers/
│   ├── auth_controller.go
│   ├── comment_controller.go
│   └── post_controller.go
├── middlewares/
│   └── auth.go
├── models/
│   ├── comment.go
│   ├── post.go
│   └── user.go
├── routes/
│   └── routes.go
├── utils/
│   ├── jwt.go
│   └── response.go
├── go.mod
├── go.sum
└── main.go
```

## 2. 数据库模型定义 (models/)

### models/user.go

```go
package models

import (
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username string `gorm:"unique;not null" json:"username"`
	Password string `gorm:"not null" json:"-"`
	Email    string `gorm:"unique;not null" json:"email"`
	Posts    []Post `gorm:"foreignKey:UserID" json:"-"`
	Comments []Comment `gorm:"foreignKey:UserID" json:"-"`
}

func (user *User) HashPassword(password string) error {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return err
	}
	user.Password = string(bytes)
	return nil
}

func (user *User) CheckPassword(providedPassword string) error {
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(providedPassword))
	if err != nil {
		return err
	}
	return nil
}
```

### models/post.go

```go
package models

import "gorm.io/gorm"

type Post struct {
	gorm.Model
	Title   string    `gorm:"not null" json:"title"`
	Content string    `gorm:"not null;type:text" json:"content"`
	UserID  uint      `gorm:"not null" json:"user_id"`
	User    User      `gorm:"foreignKey:UserID" json:"user"`
	Comments []Comment `gorm:"foreignKey:PostID" json:"comments"`
}
```

### models/comment.go

```go
package models

import "gorm.io/gorm"

type Comment struct {
	gorm.Model
	Content string `gorm:"not null" json:"content"`
	UserID  uint   `gorm:"not null" json:"user_id"`
	PostID  uint   `gorm:"not null" json:"post_id"`
	User    User   `gorm:"foreignKey:UserID" json:"user"`
	Post    Post   `gorm:"foreignKey:PostID" json:"-"`
}
```

## 3. 配置 (config/config.go)

```go
package config

import (
	"log"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func ConnectDB() {
	var err error
	dsn := os.Getenv("DB_DSN")
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})

	if err != nil {
		log.Fatal("Failed to connect to the Database")
	}
	log.Println("Connected Successfully to the Database")

	DB.AutoMigrate(&models.User{}, &models.Post{}, &models.Comment{})
	log.Println("Database Migrated")
}
```

## 4. JWT 工具 (utils/jwt.go)

```go
package utils

import (
	"time"
	"os"
	"github.com/golang-jwt/jwt/v5"
)

var jwtKey = []byte(os.Getenv("JWT_SECRET"))

type Claims struct {
	UserID uint `json:"user_id"`
	jwt.RegisteredClaims
}

func GenerateToken(userID uint) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)

	return tokenString, err
}

func ValidateToken(tokenString string) (*Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, jwt.ErrSignatureInvalid
	}

	return claims, nil
}
```

## 5. 认证中间件 (middlewares/auth.go)

```go
package middlewares

import (
	"net/http"
	"strings"
	"utils"
	"github.com/gin-gonic/gin"
)

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Bearer token not found"})
			return
		}

		claims, err := utils.ValidateToken(tokenString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		c.Set("user_id", claims.UserID)
		c.Next()
	}
}
```

## 6. 响应工具 (utils/response.go)

```go
package utils

import "github.com/gin-gonic/gin"

type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

func SuccessResponse(c *gin.Context, statusCode int, message string, data interface{}) {
	c.JSON(statusCode, Response{
		Success: true,
		Message: message,
		Data:    data,
	})
}

func ErrorResponse(c *gin.Context, statusCode int, message string, err string) {
	c.JSON(statusCode, Response{
		Success: false,
		Message: message,
		Error:   err,
	})
}
```

## 7. 控制器 (controllers/)

### auth_controller.go

```go
package controllers

import (
	"net/http"
	"models"
	"utils"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type AuthController struct {
	DB *gorm.DB
}

func NewAuthController(DB *gorm.DB) AuthController {
	return AuthController{DB}
}

func (ac *AuthController) SignUpUser(ctx *gin.Context) {
	var payload *models.User

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		utils.ErrorResponse(ctx, http.StatusBadRequest, "Invalid request payload", err.Error())
		return
	}

	hashedPassword, err := utils.HashPassword(payload.Password)
	if err != nil {
		utils.ErrorResponse(ctx, http.StatusBadRequest, "Failed to hash password", err.Error())
		return
	}

	newUser := models.User{
		Username: payload.Username,
		Email:    payload.Email,
		Password: hashedPassword,
	}

	result := ac.DB.Create(&newUser)
	if result.Error != nil {
		utils.ErrorResponse(ctx, http.StatusConflict, "User with that email or username already exists", result.Error.Error())
		return
	}

	userResponse := gin.H{
		"id":       newUser.ID,
		"username": newUser.Username,
		"email":    newUser.Email,
	}
	utils.SuccessResponse(ctx, http.StatusCreated, "User created successfully", userResponse)
}

func (ac *AuthController) SignInUser(ctx *gin.Context) {
	var payload struct {
		Email    string `json:"email" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		utils.ErrorResponse(ctx, http.StatusBadRequest, "Invalid request payload", err.Error())
		return
	}

	var user models.User
	result := ac.DB.First(&user, "email = ?", payload.Email)
	if result.Error != nil {
		utils.ErrorResponse(ctx, http.StatusBadRequest, "Invalid email or password", result.Error.Error())
		return
	}

	if err := utils.VerifyPassword(user.Password, payload.Password); err != nil {
		utils.ErrorResponse(ctx, http.StatusBadRequest, "Invalid email or password", err.Error())
		return
	}

	token, err := utils.GenerateToken(user.ID)
	if err != nil {
		utils.ErrorResponse(ctx, http.StatusInternalServerError, "Failed to generate token", err.Error())
		return
	}

	ctx.SetCookie("token", token, 3600, "/", "localhost", false, true)
	utils.SuccessResponse(ctx, http.StatusOK, "User logged in successfully", gin.H{"token": token})
}

func (ac *AuthController) GetMe(ctx *gin.Context) {
	currentUser := ctx.MustGet("currentUser").(models.User)

	userResponse := gin.H{
		"id":       currentUser.ID,
		"username": currentUser.Username,
		"email":    currentUser.Email,
	}
	utils.SuccessResponse(ctx, http.StatusOK, "User fetched successfully", userResponse)
}
```

### post_controller.go

```go
package controllers

import (
	"net/http"
	"strconv"
	"models"
	"utils"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type PostController struct {
	DB *gorm.DB
}

func NewPostController(DB *gorm.DB) PostController {
	return PostController{DB}
}

func (pc *PostController) CreatePost(ctx *gin.Context) {
	currentUser := ctx.MustGet("currentUser").(models.User)
	var payload *models.Post

	if err := ctx.ShouldBindJSON(&payload); err != nil {
		utils.ErrorResponse(ctx, http.StatusBadRequest, "Invalid request payload", err.Error())
		return
	}

	newPost := models.Post{
		Title:   payload.Title,
		Content: payload.Content,
		UserID:  currentUser.ID,
	}

	result := pc.DB.Create(&newPost)
	if result.Error != nil {
		utils.ErrorResponse(ctx, http.StatusBadGateway, "Failed to create post", result.Error.Error())
		return
	}

	utils.SuccessResponse(ctx, http.StatusCreated, "Post created successfully", newPost)
}

func (pc *PostController) UpdatePost(ctx *gin.Context) {
	postId := ctx.Param("postId")
	currentUser := ctx.MustGet("currentUser").(models.User)

	var payload *models.Post
	if err := ctx.ShouldBindJSON(&payload); err != nil {
		utils.ErrorResponse(ctx, http.StatusBadRequest, "Invalid request payload", err.Error())
		return
	}

	var updatedPost models.Post
	result := pc.DB.First(&updatedPost, "id = ?", postId)
	if result.Error != nil {
		utils.ErrorResponse(ctx, http.StatusNotFound, "Post not found", result.Error.Error())
		return
	}

	if updatedPost.UserID != currentUser.ID {
		utils.ErrorResponse(ctx, http.StatusForbidden, "You are not authorized to update this post", "")
		return
	}

	updatedPost.Title = payload.Title
	updatedPost.Content = payload.Content

	pc.DB.Save(&updatedPost)

	utils.SuccessResponse(ctx, http.StatusOK, "Post updated successfully", updatedPost)
}

func (pc *PostController) GetPost(ctx *gin.Context) {
	postId := ctx.Param("postId")

	var post models.Post
	result := pc.DB.Preload("User").Preload("Comments.User").First(&post, "id = ?", postId)
	if result.Error != nil {
		utils.ErrorResponse(ctx, http.StatusNotFound, "Post not found", result.Error.Error())
		return
	}

	utils.SuccessResponse(ctx, http.StatusOK, "Post fetched successfully", post)
}

func (pc *PostController) GetPosts(ctx *gin.Context) {
	var posts []models.Post
	results := pc.DB.Preload("User").Find(&posts)
	if results.Error != nil {
		utils.ErrorResponse(ctx, http.StatusBadGateway, "Failed to fetch posts", results.Error.Error())
		return
	}

	utils.SuccessResponse(ctx, http.StatusOK, "Posts fetched successfully", posts)
}

func (pc *PostController) DeletePost(ctx *gin.Context) {
	postId := ctx.Param("postId")
	currentUser := ctx.MustGet("currentUser").(models.User)

	var post models.Post
	result := pc.DB.First(&post, "id = ?", postId)
	if result.Error != nil {
		utils.ErrorResponse(ctx, http.StatusNotFound, "Post not found", result.Error.Error())
		return
	}

	if post.UserID != currentUser.ID {
		utils.ErrorResponse(ctx, http.StatusForbidden, "You are not authorized to delete this post", "")
		return
	}

	result = pc.DB.Delete(&post)
	if result.Error != nil {
		utils.ErrorResponse(ctx, http.StatusBadGateway, "Failed to delete post", result.Error.Error())
		return
	}

	utils.SuccessResponse(ctx, http.StatusOK, "Post deleted successfully", nil)
}
```

### comment_controller.go

```go
package controllers

import (
	"net/http"
	"strconv"
	"models"
	"utils"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type CommentController struct {
	DB *gorm.DB
}

func NewCommentController(DB *gorm.DB) CommentController {
	return CommentController{DB}
}

func (cc *CommentController) CreateComment(ctx *gin.Context) {
	postId := ctx.Param("postId")
	currentUser := ctx.MustGet("currentUser").(models.User)

	var payload *models.Comment
	if err := ctx.ShouldBindJSON(&payload); err != nil {
		utils.ErrorResponse(ctx, http.StatusBadRequest, "Invalid request payload", err.Error())
		return
	}

	postID, err := strconv.Atoi(postId)
	if err != nil {
		utils.ErrorResponse(ctx, http.StatusBadRequest, "Invalid post ID", err.Error())
		return
	}

	newComment := models.Comment{
		Content: payload.Content,
		UserID:  currentUser.ID,
		PostID:  uint(postID),
	}

	result := cc.DB.Create(&newComment)
	if result.Error != nil {
		utils.ErrorResponse(ctx, http.StatusBadGateway, "Failed to create comment", result.Error.Error())
		return
	}

	utils.SuccessResponse(ctx, http.StatusCreated, "Comment created successfully", newComment)
}

func (cc *CommentController) GetComments(ctx *gin.Context) {
	postId := ctx.Param("postId")

	var comments []models.Comment
	results := cc.DB.Preload("User").Where("post_id = ?", postId).Find(&comments)
	if results.Error != nil {
		utils.ErrorResponse(ctx, http.StatusBadGateway, "Failed to fetch comments", results.Error.Error())
		return
	}

	utils.SuccessResponse(ctx, http.StatusOK, "Comments fetched successfully", comments)
}
```

## 8. 路由 (routes/routes.go)

```go
package routes

import (
	"controllers"
	"middlewares"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func SetupRoutes(db *gorm.DB) *gin.Engine {
	r := gin.Default()

	authController := controllers.NewAuthController(db)
	postController := controllers.NewPostController(db)
	commentController := controllers.NewCommentController(db)

	// Auth routes
	r.POST("/auth/signup", authController.SignUpUser)
	r.POST("/auth/signin", authController.SignInUser)

	// User routes
	userRoutes := r.Group("/users")
	userRoutes.Use(middlewares.AuthMiddleware())
	{
		userRoutes.GET("/me", authController.GetMe)
	}

	// Post routes
	postRoutes := r.Group("/posts")
	{
		postRoutes.GET("/", postController.GetPosts)
		postRoutes.GET("/:postId", postController.GetPost)
		
		// Protected routes
		postRoutes.Use(middlewares.AuthMiddleware())
		{
			postRoutes.POST("/", postController.CreatePost)
			postRoutes.PUT("/:postId", postController.UpdatePost)
			postRoutes.DELETE("/:postId", postController.DeletePost)
		}
	}

	// Comment routes
	commentRoutes := r.Group("/posts/:postId/comments")
	{
		commentRoutes.GET("/", commentController.GetComments)
		
		// Protected routes
		commentRoutes.Use(middlewares.AuthMiddleware())
		{
			commentRoutes.POST("/", commentController.CreateComment)
		}
	}

	return r
}
```

## 9. 主程序 (main.go)

```go
package main

import (
	"log"
	"os"
	"config"
	"routes"
)

func main() {
	// Load environment variables
	if os.Getenv("DB_DSN") == "" || os.Getenv("JWT_SECRET") == "" {
		log.Fatal("Please set DB_DSN and JWT_SECRET environment variables")
	}

	// Initialize database
	config.ConnectDB()

	// Initialize router
	router := routes.SetupRoutes(config.DB)

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server starting on port %s", port)
	log.Fatal(router.Run(":" + port))
}
```

## 10. 环境变量示例

创建 `.env` 文件：

```
DB_DSN=postgres://username:password@localhost:5432/blog_db?sslmode=disable
JWT_SECRET=your_jwt_secret_key_here
PORT=8080
```

## 11. 使用说明

1. 安装依赖：
```bash
go mod init blog-backend
go get -u github.com/gin-gonic/gin
go get -u gorm.io/gorm
go get -u gorm.io/driver/postgres
go get -u github.com/golang-jwt/jwt/v5
go get -u golang.org/x/crypto/bcrypt
```

2. 运行程序：
```bash
go run main.go
```

## 12. API 端点

### 用户认证
- `POST /auth/signup` - 用户注册
- `POST /auth/signin` - 用户登录
- `GET /users/me` - 获取当前用户信息 (需要认证)

### 文章管理
- `GET /posts` - 获取所有文章
- `GET /posts/:postId` - 获取单个文章
- `POST /posts` - 创建文章 (需要认证)
- `PUT /posts/:postId` - 更新文章 (需要认证，只能更新自己的文章)
- `DELETE /posts/:postId` - 删除文章 (需要认证，只能删除自己的文章)

### 评论管理
- `GET /posts/:postId/comments` - 获取文章的所有评论
- `POST /posts/:postId/comments` - 创建评论 (需要认证)

## 13. 错误处理

系统会返回统一的错误格式：
```json
{
  "success": false,
  "message": "Error message",
  "error": "Detailed error description"
}
```

## 14. 日志记录

Gin 默认会记录 HTTP 请求日志，其他错误会在控制器中通过 `log` 包记录。

这个实现提供了完整的博客系统后端功能，包括用户认证、文章管理和评论功能，遵循 RESTful 设计原则，并使用了 JWT 进行认证。