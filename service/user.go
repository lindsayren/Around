package main

import (
      elastic "gopkg.in/olivere/elastic.v3"

      "encoding/json"
      "fmt"
      "net/http"
      "reflect"
      "time"

      "github.com/dgrijalva/jwt-go"
)

const (
      TYPE_USER = "user"
)

type User struct {
      Username string `json:"username"`
      Password string `json:"password"`
      Age int `json:"age"`
      Gender string `json:"gender"`
}
func checkUser(username, password string) bool {
      es_client, err := elastic.NewClient(elastic.SetURL(ES_URL), elastic.SetSniff(false))
      if err != nil {
            fmt.Printf("ES is not setup %v\n", err)
            return false
      }

      // Search with a term query
      termQuery := elastic.NewTermQuery("username", username)
      queryResult, err := es_client.Search().
          Index(INDEX).
          Query(termQuery).
          Pretty(true).
          Do()
      if err != nil {
            fmt.Printf("ES query failed %v\n", err)
            return false
      }

      var tyu User
      for _, item := range queryResult.Each(reflect.TypeOf(tyu)) {
            u := item.(User)
            return u.Password == password && u.Username == username
      }
      // If no user exist, return false.
      return false
}
// Add a new user. Return true if successfully.
func addUser(user User) bool {
      //和上一步一样用ES
      //Step 1:检测ES是否可用 ，elastic.SetSniff(false); 如果是true，Sniff支持一个回调机制（回调函数），统计功能
      //Step 2:检测用户是否存在
      //TotalHits >0, 说明用户已经存在
      //Step 3:用户不存在， 把用户加入到ES，和提交用户数据的流程一样
      //Index 说明是around的project
      //const:说明是user表 Refresh(true)如果一致，用新数据
      // In theory, BigTable is a better option for storing user credentials than ES. However,
      // since BT is more expensive than ES so usually students will disable BT.
      es_client, err := elastic.NewClient(elastic.SetURL(ES_URL), elastic.SetSniff(false))
      if err != nil {
            fmt.Printf("ES is not setup %v\n", err)
            return false
      }

      // Search with a term query
      termQuery := elastic.NewTermQuery("username", user.Username)
      queryResult, err := es_client.Search().
          Index(INDEX).
          Query(termQuery).
          Pretty(true).
          Do()
      if err != nil {
            fmt.Printf("ES query failed %v\n", err)
            return false
      }

      if queryResult.TotalHits() > 0 {
            fmt.Printf("User %s has existed, cannot create duplicate user.\n", user.Username)
            return false
      }

      // Save it to index
      _, err = es_client.Index().
          Index(INDEX).

          Type(TYPE_USER).
          Id(user.Username).
          BodyJson(user).
          Refresh(true).
          Do()
      if err != nil {
            fmt.Printf("ES save failed %v\n", err)
            return false
      }
      return true
      //If signup is successful, a new session is created.

}
// If login is successful, a new token is created
func signupHandler(w http.ResponseWriter, r *http.Request) {
      fmt.Println("Received one signup request")

      decoder := json.NewDecoder(r.Body)
      var u User
      if err := decoder.Decode(&u); err != nil {
            panic(err)
            return
      }

      if u.Username != "" && u.Password != "" {
            if addUser(u) {
                  fmt.Println("User added successfully.")
                  w.Write([]byte("User added successfully."))
            } else {
                  fmt.Println("Failed to add a new user.")
                  http.Error(w, "Failed to add a new user", http.StatusInternalServerError)
            }
      } else {
            fmt.Println("Empty password or username.")
            http.Error(w, "Empty password or username", http.StatusInternalServerError)
      }

      w.Header().Set("Content-Type", "text/plain")
      w.Header().Set("Access-Control-Allow-Origin", "*")
}

// If login is successful, a new token is created.
//1 获取用户提交json信息
//2 验证用户信息
//3 生成token
//claims 是payload，转换成map操作
//把用户名加入 .Unix() 纪元时间，从19700101到现在一共走了多少秒
func loginHandler(w http.ResponseWriter, r *http.Request) {
      fmt.Println("Received one login request")

      decoder := json.NewDecoder(r.Body)
      var u User
      if err := decoder.Decode(&u); err != nil {
            panic(err)
            return
      }

      if checkUser(u.Username, u.Password) {
            token := jwt.New(jwt.SigningMethodHS256)
            claims := token.Claims.(jwt.MapClaims)
            /* Set token claims */
            claims["username"] = u.Username
            claims["exp"] = time.Now().Add(time.Hour * 24).Unix()

            /* Sign the token with our secret 定义在main.go*/
            tokenString, _ := token.SignedString(mySigningKey)

            /* Finally, write the token to the browser window 返回token给用户，下次登录要带着token，否则会显示登录失败*/
            w.Write([]byte(tokenString))
      } else {
            fmt.Println("Invalid password or username.")
            http.Error(w, "Invalid password or username", http.StatusForbidden)
      }

      w.Header().Set("Content-Type", "text/plain")
      w.Header().Set("Access-Control-Allow-Origin", "*")
}






