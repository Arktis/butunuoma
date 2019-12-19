package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

var secret = []byte("mysecret")

//var mySigningKey = []byte("captainjacksparrowsayshi")

type User struct {
	name     string
	password string
}
type Building struct {
	ID      string `json:"buildingId"`
	Address string `json:"address"`
	//Apartaments []Apartament
}

type Apartament struct {
	ID         string `json:"apartamentID"`
	BuildingID string `json:"buildingID"`
	Num        string `json:"apartamentNumber"`
	//Contracts  Contract
	//contracts []Contract
}

type Contract struct {
	ID           string `json:"contractID"`
	ApartamentID string `json:"apartamentID"`
	BuildingID   string `json:"buildingID"`
	StartDate    string `json:"startDate"`
	EndDate      string `json:"endDate"`
}

//Init books var as a slice(variable lenght array) Book struct
//var books []Book
var buildings []Building
var apartaments []Apartament
var contracts []Contract
var buildingID = 2
var apartamentID = 4
var contractID = 4
var apartamentCount = 0
var contractCount = 0

func returnCode200(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

//created successfully
func returnCode201(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusCreated)
}

//deleted successfully
func returnCode204(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}
func returnCode400(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusBadRequest)
}

func returnCode404(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
}

//Get all buildings
func getBuildings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	db := connectToDB()
	defer db.Close()
	rows, err := db.Query("SELECT * FROM building")
	if err != nil {
		log.Fatal(err)

	}
	defer rows.Close()

	var (
		ID      string
		Address string
	)

	var buildingg []Building
	var b Building
	i := -1
	for rows.Next() {
		i++
		err := rows.Scan(&ID, &Address)
		if err != nil {
			log.Fatal(err)
		}
		b.ID = ID
		b.Address = Address
		buildingg = append(buildingg, b)
		log.Println(ID, Address)
	}
	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}
	if len(buildingg) == 0 {
		returnCode404(w, r)
	} else {
		returnCode200(w, r)
		json.NewEncoder(w).Encode(buildingg)
	}
}

func getBuilding(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r) //Get params

	db := connectToDB()
	defer db.Close()

	var (
		Address string
	)

	row := db.QueryRow("SELECT Address FROM building WHERE ID='" + params["id3"] + "'")
	switch err := row.Scan(&Address); err {
	case sql.ErrNoRows:
		returnCode404(w, r)
	case nil:
		var buildingg []Building
		var b Building
		b.ID = params["id3"]
		b.Address = Address
		buildingg = append(buildingg, b)
		json.NewEncoder(w).Encode(buildingg)
		//fmt.Println(Address)
	default:
		panic(err)
	}
}

// Create a Building
//func createBuilding(w http.ResponseWriter, r *http.Request) {
var createBuilding = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var building Building
	_ = json.NewDecoder(r.Body).Decode(&building)

	building.ID = strconv.Itoa(buildingID)
	buildingID = buildingID + 1

	if building.Address != "" {
		db := connectToDB()
		defer db.Close()
		returnCode200(w, r)
		db.Exec("INSERT INTO building VALUES ('" + strconv.Itoa(buildingID) + "','" + building.Address + "')")
		//w.Write([]byte("building created"))
		//buildings = append(buildings, building)
		//json.NewEncoder(w).Encode(building)
	} else {
		returnCode400(w, r)
	}

})

//func updateBuilding(w http.ResponseWriter, r *http.Request) {
var updateBuilding = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	//found := false
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	db := connectToDB()
	defer db.Close()
	var (
		Address string
	)
	row := db.QueryRow("SELECT Address FROM building WHERE ID='" + params["id3"] + "'")
	switch err := row.Scan(&Address); err {
	case sql.ErrNoRows:
		returnCode404(w, r)
	case nil:
		var building Building
		_ = json.NewDecoder(r.Body).Decode(&building)
		if building.Address != "" {
			db.Exec("UPDATE building SET Address ='" + building.Address + "' WHERE ID='" + params["id3"] + "'")
		}
		returnCode200(w, r)
		//w.Write([]byte("building updated"))
		//fmt.Println(Address)
	default:
		panic(err)
	}

})

//func deleteBuilding(w http.ResponseWriter, r *http.Request) {
var deleteBuilding = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	//found := false
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r) //for building's id
	db := connectToDB()
	defer db.Close()
	var (
		Address string
	)
	row := db.QueryRow("SELECT Address FROM building WHERE ID='" + params["id3"] + "'")
	switch err := row.Scan(&Address); err {
	case sql.ErrNoRows:
		returnCode404(w, r)
	case nil:
		db.Exec("DELETE FROM building WHERE ID='" + params["id3"] + "'")
		returnCode204(w, r)
	//fmt.Println(Address)
	default:
		panic(err)
	}
})

func getApartaments(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r) //for building's id
	db := connectToDB()
	defer db.Close()
	rows, err := db.Query("SELECT * FROM apartament WHERE BuildingID = '" + params["id3"] + "'")
	if err != nil {
		log.Fatal(err)

	}
	defer rows.Close()
	var (
		ID         string
		BuildingID string
		Num        string
	)
	var apartamentt []Apartament
	var a Apartament
	i := -1
	for rows.Next() {
		i++
		err := rows.Scan(&ID, &BuildingID, &Num)
		if err != nil {
			log.Fatal(err)
		}
		a.ID = ID
		a.BuildingID = BuildingID
		a.Num = Num
		apartamentt = append(apartamentt, a)
		//log.Println(ID, buildingID, Num)
	}
	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}
	if len(apartamentt) == 0 {
		returnCode404(w, r)
	} else {
		returnCode200(w, r)
		json.NewEncoder(w).Encode(apartamentt)
	}
}

func getApartament(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r) //Get params
	db := connectToDB()
	defer db.Close()
	var (
		//ID         string
		//BuildingID string
		Num string
	)
	row := db.QueryRow("SELECT Num FROM apartament WHERE ID='" + params["id2"] + "' AND BuildingID='" + params["id3"] + "'")
	switch err := row.Scan(&Num); err {
	case sql.ErrNoRows:
		returnCode404(w, r)
	case nil:
		var apartamentt []Apartament
		var a Apartament
		a.ID = params["id2"]
		a.BuildingID = params["id3"]
		a.Num = Num
		apartamentt = append(apartamentt, a)
		json.NewEncoder(w).Encode(apartamentt)
		//fmt.Println(Address)
	default:
		panic(err)
	}
}

// Create a Apartament
var createApartament = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	//func createApartament(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var apartament Apartament
	_ = json.NewDecoder(r.Body).Decode(&apartament)
	apartament.ID = strconv.Itoa(apartamentID)
	//apartaments = append(apartaments, apartament)
	params := mux.Vars(r)

	_ = json.NewDecoder(r.Body).Decode(&apartament)

	apartament.ID = strconv.Itoa(buildingID)
	apartamentID = apartamentID + 1
	if apartament.Num != "" {
		db := connectToDB()
		defer db.Close()
		returnCode200(w, r)
		db.Exec("INSERT INTO apartament VALUES ('" + strconv.Itoa(apartamentID) + "','" + params["id3"] + "','" + apartament.Num + "')")
	} else {
		returnCode400(w, r)
	}
})

var updateApartament = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	//func updateApartament(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	db := connectToDB()
	defer db.Close()
	//num := "123456789"

	// db.Exec("UPDATE apartament SET Num ='" + num + "' WHERE ID='" + params["id2"] + "' AND BuildingID='" + params["id3"] + "'")
	// println("UPDATE apartament SET Num ='" + num + "' WHERE ID='" + params["id2"] + "' AND BuildingID='" + params["id3"] + "'")
	var (
		Num string
	)
	row := db.QueryRow("SELECT Num FROM apartament WHERE ID='" + params["id2"] + "' AND BuildingID='" + params["id3"] + "'")
	switch err := row.Scan(&Num); err {
	case sql.ErrNoRows:
		returnCode404(w, r)
	case nil:
		var apartament Apartament
		_ = json.NewDecoder(r.Body).Decode(&apartament)
		if apartament.Num != "" {
			//num := "asd"

			db.Exec("UPDATE apartament SET Num ='" + apartament.Num + "' WHERE ID='" + params["id2"] + "' AND BuildingID='" + params["id3"] + "'")
			println("changed")
		}
		returnCode200(w, r)
	default:
		panic(err)
	}
})

var deleteApartament = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	//func deleteApartament(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	db := connectToDB()
	defer db.Close()
	var (
		Num string
	)
	row := db.QueryRow("SELECT Num FROM apartament WHERE ID='" + params["id2"] + "' AND BuildingID='" + params["id3"] + "'")
	switch err := row.Scan(&Num); err {
	case sql.ErrNoRows:
		returnCode404(w, r)
	case nil:
		db.Exec("DELETE FROM apartament WHERE ID='" + params["id2"] + "' AND BuildingID='" + params["id3"] + "'")
		returnCode204(w, r)
	//fmt.Println(Address)
	default:
		panic(err)
	}
})

func getContracts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	db := connectToDB()
	defer db.Close()
	params := mux.Vars(r)
	rows, err := db.Query("SELECT * FROM contract WHERE BuildingID = '" + params["id3"] + "' AND ApartamentID = '" + params["id2"] + "'")
	if err != nil {
		log.Fatal(err)

	}
	defer rows.Close()
	var (
		ApartamentID string
		BuildingID   string
		ID           string
		StartDate    string
		EndDate      string
	)
	var contractt []Contract
	var c Contract
	i := -1
	for rows.Next() {
		i++
		err := rows.Scan(&ID, &BuildingID, &ApartamentID, &StartDate, &EndDate)
		if err != nil {
			log.Fatal(err)
		}
		c.ID = ID
		c.BuildingID = BuildingID
		c.ApartamentID = ApartamentID
		c.StartDate = StartDate
		c.EndDate = EndDate
		contractt = append(contractt, c)
		//log.Println(ID, buildingID, Num)
	}
	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}
	if len(contractt) == 0 {
		returnCode404(w, r)
	} else {
		returnCode200(w, r)
		json.NewEncoder(w).Encode(contractt)
	}
}

func getContract(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r) //Get params
	db := connectToDB()
	defer db.Close()
	var (
		ApartamentID string
		BuildingID   string
		ID           string
		StartDate    string
		EndDate      string
	)
	row := db.QueryRow("SELECT * FROM contract WHERE ID='" + params["id"] + "' AND BuildingID='" + params["id3"] + "' AND ApartamentID='" + params["id2"] + "'")
	switch err := row.Scan(&ID, &BuildingID, &ApartamentID, &StartDate, &EndDate); err {
	case sql.ErrNoRows:
		returnCode404(w, r)
	case nil:
		var contractt []Contract
		var c Contract
		c.ID = ID
		c.BuildingID = BuildingID
		c.ApartamentID = ApartamentID
		c.StartDate = StartDate
		c.EndDate = EndDate
		contractt = append(contractt, c)
		json.NewEncoder(w).Encode(contractt)
		//fmt.Println(Address)
	default:
		panic(err)
	}
}

// Create a Apartament
var createContract = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	//func createContract(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var contract Contract
	_ = json.NewDecoder(r.Body).Decode(&contract)
	contractID = contractID + 1
	contract.ID = strconv.Itoa(contractID)
	//contract = append(contracts, contract)
	params := mux.Vars(r)

	_ = json.NewDecoder(r.Body).Decode(&contract)

	contract.ID = strconv.Itoa(contractID)
	if contract.StartDate != "" && contract.EndDate != "" {
		db := connectToDB()
		defer db.Close()
		returnCode200(w, r)
		db.Exec("INSERT INTO contract VALUES ('" + strconv.Itoa(contractID) + "','" + params["id3"] + "','" + params["id2"] + "','" + contract.StartDate + "','" + contract.EndDate + "')")
	} else {
		returnCode400(w, r)
	}
})

var updateContract = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	//func updateContract(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	db := connectToDB()
	defer db.Close()
	var (
		StartDate string
		//EndDate string
	)
	row := db.QueryRow("SELECT StartDate FROM contract WHERE ID='" + params["id"] + "' AND BuildingID='" + params["id3"] + "' AND ApartamentID='" + params["id2"] + "'")
	switch err := row.Scan(&StartDate); err {
	case sql.ErrNoRows:
		returnCode404(w, r)
	case nil:
		var contract Contract
		_ = json.NewDecoder(r.Body).Decode(&contract)
		if contract.StartDate != "" && contract.EndDate != "" {
			db.Exec("UPDATE contract SET StartDate ='" + contract.StartDate + "', EndDate ='" + contract.EndDate + "' WHERE ID='" + params["id"] + "' AND BuildingID='" + params["id3"] + "' AND ApartamentID='" + params["id2"] + "'")
		}
		returnCode200(w, r)
	default:
		panic(err)
	}
})

var deleteContract = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	//func deleteContract(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	db := connectToDB()
	defer db.Close()
	var (
		StartDate string
	)
	row := db.QueryRow("SELECT StartDate FROM contract WHERE ID='" + params["id"] + "' AND BuildingID='" + params["id3"] + "' AND ApartamentID='" + params["id2"] + "'")
	switch err := row.Scan(&StartDate); err {
	case sql.ErrNoRows:
		returnCode404(w, r)
	case nil:
		db.Exec("DELETE FROM contract WHERE ID='" + params["id"] + "' AND BuildingID='" + params["id3"] + "' AND ApartamentID='" + params["id2"] + "'")
		returnCode204(w, r)
	//fmt.Println(Address)
	default:
		panic(err)
	}
})

func authMiddlewareAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		tokenString := r.Header.Get("Token")
		if len(tokenString) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Missing Authorization Header"))
			return
		}
		// protection against code reading?
		tokenString = strings.Replace(tokenString, "Bearer", "", 1)
		_, err := verifyToken(tokenString)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Error verifying JWT token: " + err.Error()))
			return
		}
		//name := claims.(jwt.MapClaims)["name"].(string)
		//role := claims.(jwt.MapClaims)["role"].(string)

		//r.Header.Set("name", name)
		//r.Header.Set("role", role)
		claims, ok := extractClaims(tokenString)
		role := claims["role"].(string)
		//w.Write([]byte(claims["role"].(string)))
		if role == "user" {
			w.Write([]byte("This task is only meant for admin"))
			return
		}
		if role == "admin" && ok == true {
			w.Write([]byte("User authenticated. Proceeding with request."))
			next.ServeHTTP(w, r)
		}

	})
}
func extractClaims(tokenStr string) (jwt.MapClaims, bool) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		// check token signing method etc
		return secret, nil
	})

	if err != nil {
		return nil, false
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, true
	} else {
		log.Printf("Invalid JWT Token")
		return nil, false
	}
}
func authMiddlewareUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		tokenString := r.Header.Get("Token")

		if len(tokenString) == 0 {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Missing Authorization Header"))
			return
		}
		// protection against code reading?
		tokenString = strings.Replace(tokenString, "Bearer", "", 1)
		_, err := verifyToken(tokenString)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Error verifying JWT token: " + err.Error()))
			return
		}
		claims, ok := extractClaims(tokenString)
		role := claims["role"].(string)
		w.Write([]byte(claims["name"].(string)))
		if (role == "admin" || role == "user") && ok == true {
			w.Write([]byte("User authenticated. Proceeding with request."))
			//w.Write([]byte(claims["name"].(string)))
			next.ServeHTTP(w, r)
		} else {
			w.Write([]byte("Failed to get claims"))
			return
		}
	})
}
func register(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	if params["name"] != "" && params["password"] != "" {
		db := connectToDB()
		defer db.Close()
		returnCode200(w, r)
		db.Exec("INSERT INTO user VALUES ('" + params["name"] + "','" + params["password"] + "','user')")
		w.Write([]byte("User successfully registered"))
	} else {
		returnCode400(w, r)
	}
}

//returns JWT to used after he logs in
func getJWT(w http.ResponseWriter, r *http.Request) {
	//w.Header().Set("Content-Type", "application/json")
	//w.Write([]byte("JWT generated"))
	params := mux.Vars(r) //Get params
	db := connectToDB()
	defer db.Close()
	var (
		role string
		//password string
	)
	row := db.QueryRow("SELECT role FROM user WHERE name='" + params["name"] + "' AND password='" + params["password"] + "'")
	switch err := row.Scan(&role); err {
	case sql.ErrNoRows:
		returnCode404(w, r)
	case nil:
		//If user exists, create jwt and print it to him
		jwtToken := createAndEncodeJWT(params["name"], role)
		//println(paramas["role"])
		//w.Write([]byte(role))
		w.Write([]byte(jwtToken))
		returnCode200(w, r)
	default:
		panic(err)
	}
}

//Generates JWT
func createAndEncodeJWT(name string, role string) string {
	// Create a new token object, specifying signing method and the claims
	// you would like it to contain.
	t0 := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"name":     name,
		"signedAt": t0,
		"exp":      time.Now().Add(time.Second * 600).Unix(),
		"role":     role,
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(secret)
	//fmt.Println(time.Now().Second() * 10)
	fmt.Println(tokenString, err)
	return tokenString
}

//Checks if jwt was not changed
func verifyToken(tokenString string) (jwt.Claims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	return token.Claims, err
}

func ConfigureRouter() *mux.Router {
	r := mux.NewRouter()

	//router.PathPrefix("/static").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))
	r.HandleFunc("/api/login/name/{name}/password/{password}", getJWT).Methods("POST")
	r.HandleFunc("/api/register/name/{name}/password/{password}", register).Methods("POST")
	r.HandleFunc("/api/buildings", getBuildings).Methods("GET")
	r.HandleFunc("/api/buildings/{id3}", getBuilding).Methods("GET")
	r.Handle("/api/buildings", authMiddlewareUser(createBuilding)).Methods("POST")
	r.Handle("/api/buildings/{id3}", authMiddlewareAdmin(updateBuilding)).Methods("PUT")
	r.Handle("/api/buildings/{id3}", authMiddlewareAdmin(deleteBuilding)).Methods("DELETE")

	r.HandleFunc("/api/buildings/{id3}/apartaments", getApartaments).Methods("GET")
	r.HandleFunc("/api/buildings/{id3}/apartaments/{id2}", getApartament).Methods("GET")
	r.Handle("/api/buildings/{id3}/apartaments", authMiddlewareUser(createApartament)).Methods("POST")
	r.Handle("/api/buildings/{id3}/apartaments/{id2}", authMiddlewareAdmin(updateApartament)).Methods("PUT")
	r.Handle("/api/buildings/{id3}/apartaments/{id2}", authMiddlewareAdmin(deleteApartament)).Methods("DELETE")

	r.HandleFunc("/api/buildings/{id3}/apartaments/{id2}/contracts", getContracts).Methods("GET")
	r.HandleFunc("/api/buildings/{id3}/apartaments/{id2}/contracts/{id}", getContract).Methods("GET")
	r.Handle("/api/buildings/{id3}/apartaments/{id2}/contracts", authMiddlewareUser(createContract)).Methods("POST")
	r.Handle("/api/buildings/{id3}/apartaments/{id2}/contracts/{id}", authMiddlewareAdmin(updateContract)).Methods("PUT")
	r.Handle("/api/buildings/{id3}/apartaments/{id2}/contracts/{id}", authMiddlewareAdmin(deleteContract)).Methods("DELETE")

	return r
}

func mocData() {
	var apartamentsB1 []Apartament
	var apartamentsB2 []Apartament
	var contractsA11 Contract
	var contractsA12 Contract
	var contractsA21 Contract
	var contractsA22 Contract
	contractsA11.ID = "1"
	contractsA11.StartDate = "2021-10-20"
	contractsA11.ApartamentID = "1"
	contractsA11.EndDate = "2022-10-20"
	contractsA11.BuildingID = "1"
	contractsA12.ID = "2"
	contractsA12.ApartamentID = "2"
	contractsA12.StartDate = "2025-10-20"
	contractsA12.EndDate = "2026-10-20"
	contractsA12.BuildingID = "1"
	contractsA21.ID = "3"
	contractsA21.ApartamentID = "3"
	contractsA21.StartDate = "2021-10-20"
	contractsA21.EndDate = "2027-10-20"
	contractsA21.BuildingID = "2"
	contractsA22.ID = "4"
	contractsA22.ApartamentID = "4"
	contractsA22.StartDate = "2077-10-20"
	contractsA22.EndDate = "2030-10-20"
	contractsA22.BuildingID = "2"
	apartamentsB1 = append(apartamentsB1, Apartament{ID: "1", BuildingID: "1", Num: "545" /* , Contracts: contractsA11 */})
	apartamentsB1 = append(apartamentsB1, Apartament{ID: "2", BuildingID: "1", Num: "245" /* , Contracts: contractsA12 */})
	apartamentsB2 = append(apartamentsB2, Apartament{ID: "3", BuildingID: "2", Num: "3456" /* , Contracts: contractsA21 */})
	apartamentsB2 = append(apartamentsB2, Apartament{ID: "4", BuildingID: "2", Num: "4987" /* , Contracts: contractsA22 */})
	apartaments = append(apartaments, apartamentsB1[0])
	apartaments = append(apartaments, apartamentsB1[1])
	apartaments = append(apartaments, apartamentsB2[0])
	apartaments = append(apartaments, apartamentsB2[1])
	contracts = append(contracts, contractsA11)
	contracts = append(contracts, contractsA12)
	contracts = append(contracts, contractsA21)
	contracts = append(contracts, contractsA22)

	buildings = append(buildings, Building{ID: "1", Address: "gatve-1" /* , Apartaments: apartamentsB1 */})
	buildings = append(buildings, Building{ID: "2", Address: "gatve-2" /* , Apartaments: apartamentsB2 */})

}
func handleRequests() {
	router := ConfigureRouter()
	log.Fatal(http.ListenAndServe(":9000", handlers.LoggingHandler(os.Stdout, router)))
}

func connectToDB() *sql.DB {
	db, err := sql.Open("mysql", "root:@/butunuoma")

	if err != nil {
		panic(err.Error())
	}

	//defer db.Close()

	return db
}

func main() {

	mocData()
	//token := createAndEncodeJWT("admin")
	//validateToken(token)

	handleRequests()
}
