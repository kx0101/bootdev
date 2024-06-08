package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

type DB struct {
	path string
	mux  *sync.RWMutex
}

type DBStructure struct {
	Chirps map[int]Chirp `json:"chirps"`
	Users  []User        `json:"users"`
}

type User struct {
	Password string `json:"password"`
	Email    string `json:"email"`
	Id       int    `json:"id"`
}

type Chirp struct {
	Content string `json:"body"`
	Id      int    `json:"id"`
}

func NewDB(path string) (*DB, error) {
	db := &DB{
		path: path,
		mux:  &sync.RWMutex{},
	}

	if err := db.ensureDB(); err != nil {
		return nil, err
	}

	return db, nil
}

func (db *DB) Login(user User) (User, error) {
	dbStructure, err := db.loadDB()

	if err != nil {
		return User{}, err
	}

	var userFound User
	userExists := false

	// could add a map[email]bool field for a more efficient lookup
	for _, userFromDb := range dbStructure.Users {
		if userFromDb.Email == user.Email {
			userFound = userFromDb
			userExists = true

			break
		}
	}

	if !userExists {
		return User{}, errors.New("user not found")
	}

	err = bcrypt.CompareHashAndPassword([]byte(userFound.Password), []byte(user.Password))
	if err != nil {
		return User{}, fmt.Errorf("invalid credentials")
	}

	return userFound, nil
}

func (db *DB) UpdateUser(user User) error {
	dbStructure, err := db.loadDB()

	if err != nil {
		return err
	}

	for i, userFromDb := range dbStructure.Users {
		if userFromDb.Id == user.Id {
			if user.Email != "" {
				userFromDb.Email = user.Email
			}

			if user.Password != "" {
				hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
				if err != nil {
					return nil
				}

				user.Password = string(hashedPassword)
			}

			dbStructure.Users[i] = user

			if err := db.writeDB(dbStructure); err != nil {
				return err
			}

			user.Password = ""
			return nil
		}
	}

	return fmt.Errorf("user not found")
}

func (db *DB) CreateUser(user User) (User, error) {
	dbStructure, err := db.loadDB()

	if err != nil {
		return User{}, err
	}

	// could add a map[email]bool field for a more efficient lookup
	for _, userFromDb := range dbStructure.Users {
		if userFromDb.Email == user.Email {
			return User{}, fmt.Errorf("there's already a user with that email")
		}
	}

	id := len(dbStructure.Users) + 1

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
	if err != nil {
		return User{}, err
	}

	user = User{
		Id:       id,
		Email:    user.Email,
		Password: string(hashedPassword),
	}

	dbStructure.Users = append(dbStructure.Users, user)

	if err := db.writeDB(dbStructure); err != nil {
		return User{}, err
	}

	return user, nil
}

func (db *DB) CreateChirp(body string) (Chirp, error) {
	dbStructure, err := db.loadDB()

	if err != nil {
		return Chirp{}, err
	}

	id := len(dbStructure.Chirps) + 1

	if len(body) > 140 {
		return Chirp{}, errors.New("Chirp is too long")
	}

	chirp := Chirp{
		Id:      id,
		Content: body,
	}

	if dbStructure.Chirps == nil {
		dbStructure.Chirps = make(map[int]Chirp)
	}

	dbStructure.Chirps[id] = chirp

	if err := db.writeDB(dbStructure); err != nil {
		return Chirp{}, err
	}

	return chirp, nil
}

func (db *DB) GetChirps() ([]Chirp, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return []Chirp{}, err
	}

	if dbStructure.Chirps == nil {
		return []Chirp{}, nil
	}

	var chirps []Chirp
	for _, chirp := range dbStructure.Chirps {
		chirps = append(chirps, chirp)
	}

	return chirps, nil
}

func (db *DB) GetChirp(id int) (Chirp, error) {
	dbStructure, err := db.loadDB()
	if err != nil {
		return Chirp{}, err
	}

	if dbStructure.Chirps == nil {
		return Chirp{}, nil
	}

	chirp, exists := dbStructure.Chirps[id]
	if !exists {
		return chirp, nil
	}

	return Chirp{}, fmt.Errorf("there is no chirp with id: %+v", id)
}

func (db *DB) ensureDB() error {
	db.mux.RLock()
	defer db.mux.RUnlock()

	_, err := os.Stat(db.path)

	if os.IsNotExist(err) {
		_, errCreation := os.Create(db.path)
		if errCreation != nil {
			return errCreation
		}

		db.mux.RUnlock()
		if errWrite := db.writeDB(DBStructure{}); err != nil {
			return errWrite
		}
	} else if err != nil {
		return err
	}

	return nil
}

func (db *DB) loadDB() (DBStructure, error) {
	db.mux.RLock()
	defer db.mux.RUnlock()

	var dbStructure DBStructure

	file, err := os.ReadFile(db.path)
	if err != nil {
		return DBStructure{}, err
	}

	err = json.Unmarshal(file, &dbStructure)
	if err != nil {
		return DBStructure{}, err
	}

	return dbStructure, nil
}

func (db *DB) writeDB(dbStructure DBStructure) error {
	db.mux.Lock()
	defer db.mux.Unlock()

	jsonData, err := json.MarshalIndent(dbStructure, "", "    ")
	if err != nil {
		return err
	}

	err = os.WriteFile(db.path, jsonData, 0644)
	if err != nil {
		return err
	}

	return nil
}
