package client

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/google/uuid
// - strconv
// - strings

import (
	"bytes"

	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	//"crypto/sha1"

	// Optional.
	_ "strconv"
	//"math/big"
)

var globalHmacKey = userlib.RandomBytes(16)
var globalSaltOne = userlib.RandomBytes(16)
var globalSaltTwo = userlib.RandomBytes(16)
var globalSymAccessKey = userlib.RandomBytes(16)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username      string
	Password      []byte
	UserFileSpace map[string][]byte
	PKEEncKey     userlib.PublicKeyType
	PKEDecKey     userlib.PrivateKeyType
	SymEncKey     []byte
	UserSignKey   userlib.PrivateKeyType
	SymKey        []byte //have to change this so that we have a different symKey for everyfile
	HmacKey       []byte // we also have to separate this hmackey with the one that is being shared
}

type UserAuthenticate struct {
	UsernameHashed []byte
	PasswordHashed []byte
}

// will hold all the data we need to manage the access to the files
type DataAccess struct {
	FileID      []byte //given when file gets created, will not change since
	FileName    string // might change for every user
	UserName    string
	Invitations map[string]uuid.UUID
	Padding     []byte
}

type InvitationStruct struct {
	FileName    string
	FileID      []byte
	MetaDataKey uuid.UUID
	SymKey      []byte
	IV          []byte
	HMACKey     []byte
	Padding     []byte
}
type Helper struct {
	Ciphertext      []byte
	SymKeyEncrypted []byte
	Signature       []byte
}

type Node struct {
	Content []byte
	Prev    *Node
	Next    *Node
}

type DoublyLinkedList struct {
	Head *Node
	Tail *Node
}

func (dll *DoublyLinkedList) Append(content []byte) {
	newNode := &Node{Content: content}
	if dll.Head == nil { //
		dll.Head = newNode
		dll.Tail = newNode
	} else {
		dll.Tail.Next = newNode // Set the next of current tail to new node
		newNode.Prev = dll.Tail // Set previous of new node to current tail
		dll.Tail = newNode      // Update the tail to new node
	}
}

func InitUser(username string, password string) (userdataptr *User, err error) {

	//we can delete this if we do not need it
	userEncKey, userDecKey, errPKEDGen := userlib.PKEKeyGen()
	if errPKEDGen != nil {
		return nil, errPKEDGen
	}

	//generate user signatureKey
	userSignKey, userVerSignKey, signErr := userlib.DSKeyGen()
	if signErr != nil {
		return nil, signErr
	}

	//hashing the username with HmacKey
	hmacKey := userlib.Hash([]byte("HMACKEY" + password)[:16])
	//fmt.Printf("This is the HMACkEY: " + string(hmacKey))
	usernameHashed, _ := userlib.HMACEval(hmacKey, []byte(username))
	//fmt.Printf("This is the usernameHashed: " + string(usernameHashed))
	if len(usernameHashed) > 16 {
		usernameHashed = usernameHashed[:16]
	}
	keyForDataStore, _ := uuid.FromBytes(usernameHashed)

	storedPasswordHashed, userExists := userlib.DatastoreGet(keyForDataStore)
	if userExists {
		// Hash the provided password with the same salt used during user creation
		passwordHashed := userlib.Argon2Key([]byte(password), globalSaltOne, 32)
		// Compare the hashed passwords to verify if the user with the same password exists
		if bytes.Equal(passwordHashed, storedPasswordHashed) {
			// User with the same username and password already exists, return an error
			return &User{Username: username}, nil
		}
	}
	//hashing password with salt and keylen using Argon2Key
	//using two different salts because we are storing the hashed password in the datastore
	//and we are using the same hashed with different salt as our key for symmetric key
	passwordHashed := userlib.Argon2Key([]byte(password), globalSaltOne, 32)
	userAuthenticateKey, _ := uuid.FromBytes(userlib.Hash([]byte("userAuthenticate" + username)))
	newUserAuthenticate := &UserAuthenticate{
		UsernameHashed: usernameHashed,
		PasswordHashed: passwordHashed}

	storedUserAuthenicate, _ := json.Marshal(newUserAuthenticate)
	userlib.DatastoreSet(userAuthenticateKey, storedUserAuthenicate)

	//Symmetric-Key Encryption
	userSymKey := userlib.Argon2Key([]byte(password), globalSaltTwo, 16)
	newFileSpace := make(map[string][]byte)
	iv := userlib.RandomBytes(16)
	var newUser User = User{
		Username:      username,
		Password:      passwordHashed,
		UserFileSpace: newFileSpace,
		PKEEncKey:     userEncKey,
		PKEDecKey:     userDecKey,
		UserSignKey:   userSignKey,
		SymKey:        userSymKey,
		HmacKey:       hmacKey}

	userDataBytes, err := json.Marshal(newUser)
	if err != nil {
		return nil, err
	}
	encryptedUserData := userlib.SymEnc(userSymKey, iv, userDataBytes)
	userKeyStorage, _ := uuid.FromBytes(userlib.Hash([]byte("user storage key" + username))[:16])
	userlib.DatastoreSet(userKeyStorage, encryptedUserData)

	//store user's verification signature key publicly so everyone can verify the signatures
	//will use it for the invitations

	userlib.KeystoreSet(username+"signature", userVerSignKey)
	userlib.KeystoreSet(username+"publicKey", userEncKey)

	//fmt.Println("USER CREATED: @InitUser")
	return &newUser, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	//var userdata User
	//userdataptr = &userdata
	hmacKey := userlib.Hash([]byte("HMACKEY" + password)[:16]) //generating the deterministic hmackey
	//fmt.Printf("This is the HMACkEY: " + string(hmacKey))
	usernameHashed, _ := userlib.HMACEval(hmacKey, []byte(username))
	//fmt.Printf("This is the USERNAME HASHED: " + string(usernameHashed))
	if len(usernameHashed) > 16 {
		usernameHashed = usernameHashed[:16]
	}

	userAuthenticateKey, _ := uuid.FromBytes(userlib.Hash([]byte("userAuthenticate" + username)))
	storeUserAuthenicate, ok := userlib.DatastoreGet(userAuthenticateKey)
	if !ok {
		return nil, errors.New("user not found")
	}
	newUserAuthenticate := &UserAuthenticate{}
	json.Unmarshal(storeUserAuthenicate, newUserAuthenticate)

	//keyForDataStore, _ := uuid.FromBytes(usernameHashed)

	//fmt.Printf("This is the USERNAME HASHED: " + string(usernameHashed))
	//fmt.Printf("This is the USERNAME HASHED: " + string(keyForDataStore[:16]))

	if !userlib.HMACEqual(usernameHashed, newUserAuthenticate.UsernameHashed) {
		return nil, errors.New("User not found")
	}

	passwordHashed := userlib.Argon2Key([]byte(password), globalSaltOne, 32)

	if !bytes.Equal(passwordHashed, newUserAuthenticate.PasswordHashed) {
		return nil, errors.New("password is incorrect")
	}

	userKeyStorage, _ := uuid.FromBytes(userlib.Hash([]byte("user storage key" + username))[:16])
	encryptedUserData, _ := userlib.DatastoreGet(userKeyStorage)
	userSymKey := userlib.Argon2Key([]byte(password), globalSaltTwo, 16)
	decryptedUserData := userlib.SymDec(userSymKey, encryptedUserData)

	userData := &User{}
	json.Unmarshal(decryptedUserData, userData)

	//fmt.Println("USER FOUND: @GetUser")
	return userData, nil
}

func updateUserData(userdata User, newFileName string, newID []byte) (User, error) {
	userKeyStorage, _ := uuid.FromBytes(userlib.Hash([]byte("user storage key" + userdata.Username))[:16])
	//get user data
	encryptedUserData, _ := userlib.DatastoreGet(userKeyStorage)
	//decrypt it

	decryptedUserData := userlib.SymDec(userdata.SymKey, encryptedUserData)
	updatedUser := &User{}
	//unmarshal
	errUnM := json.Unmarshal(decryptedUserData, updatedUser)
	if errUnM != nil {
		return userdata, errUnM
	}
	//make changes
	updatedUser.UserFileSpace[newFileName] = newID
	//marshal it
	marshUpdates, errMar := json.Marshal(updatedUser)
	if errMar != nil {
		return userdata, errMar
	}
	//encrypt it
	iv := userlib.RandomBytes(16)
	encUpdates := userlib.SymEnc(userdata.SymKey, iv, marshUpdates)
	//storethe update version back to DataStore
	userlib.DatastoreSet(userKeyStorage, encUpdates)

	return *updatedUser, nil
}

func getUserData(userdata User, newFileName string) (User, error) {
	userKeyStorage, _ := uuid.FromBytes(userlib.Hash([]byte("user storage key" + userdata.Username))[:16])
	//get user data
	encryptedUserData, _ := userlib.DatastoreGet(userKeyStorage)
	//decrypt it

	decryptedUserData := userlib.SymDec(userdata.SymKey, encryptedUserData)
	updatedUser := &User{}
	//unmarshal
	errUnM := json.Unmarshal(decryptedUserData, updatedUser)
	if errUnM != nil {
		return *updatedUser, errUnM
	}

	return *updatedUser, nil
}

type FileMetadata struct {
	HeadUUID uuid.UUID //UUID of the head node
	TailUUID uuid.UUID //UUID of the tail node
}
type ListNode struct {
	Content  []byte    //The actual content of the node
	NextUUID uuid.UUID //UUID of the next node
	PrevUUID uuid.UUID //UUID of the previous node
}

type EncryptedMetadataWithSig struct {
	EncryptedMetadata []byte
	Signature         []byte
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {

	fileID, inNameSpace := userdata.UserFileSpace[filename]
	if !inNameSpace {
		//if file does not exist already -> create a new access tree
		fileID = RandomBytes(25)
		userdata.UserFileSpace[filename] = fileID
		//update userData on DataStore
		newData, update := updateUserData(*userdata, filename, fileID)
		if update != nil {
			return update
		}
		userdata = &newData
		fileID = newData.UserFileSpace[filename]
		newPadding := userlib.RandomBytes(10)
		create := CreateAccessTree(userdata, filename, fileID, newPadding)
		//add fileName to user's fileName Space
		if create != nil {
			return create
		}

	}

	metadataKey, hErr := generateMetadataKey(fileID, userdata)
	if hErr != nil {
		return hErr
	}

	firstNode := ListNode{Content: content, NextUUID: uuid.Nil, PrevUUID: uuid.Nil}
	firstNodeBytes, err := json.Marshal(firstNode)
	if err != nil {
		return err
	}
	symKey := userdata.SymKey
	iv := userlib.Argon2Key([]byte(userdata.Username+string(userdata.Password)), globalSaltTwo, 16)
	encryptedNode := userlib.SymEnc(symKey, iv, firstNodeBytes)
	firstNodeUUID := uuid.New()
	userlib.DatastoreSet(firstNodeUUID, encryptedNode)

	// Set both head and tail to the first node
	fileMetadata := FileMetadata{HeadUUID: firstNodeUUID, TailUUID: firstNodeUUID}
	metadataBytes, _ := json.Marshal(fileMetadata)
	encryptedMetadata := userlib.SymEnc(symKey, iv, metadataBytes)
	signature, _ := userlib.HMACEval(symKey, encryptedMetadata)
	dataWithSig := EncryptedMetadataWithSig{
		EncryptedMetadata: encryptedMetadata,
		Signature:         signature,
	}

	dataWithSigBytes, _ := json.Marshal(dataWithSig)

	userlib.DatastoreSet(metadataKey, dataWithSigBytes)
	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {

	fileID, inNameSpace := userdata.UserFileSpace[filename]
	if !inNameSpace {
		//if file is NOT in the user's update user data  and check again
		newData, update := getUserData(*userdata, filename)
		if update != nil {
			return update
		}
		userdata = &newData
		fileID, inNameSpace = newData.UserFileSpace[filename]
		//CHECK AGAIN
		if !inNameSpace {
			return errors.New("Access Denied. No File ID @LoadFile")
		}
	}

	metadataKey, hErr := generateMetadataKey(fileID, userdata)
	if hErr != nil {
		return hErr
	}

	symKey := userdata.SymKey
	iv := userlib.Argon2Key([]byte(userdata.Username+string(userdata.Password)), globalSaltTwo, 16)

	dataWithSigBytes, ok := userlib.DatastoreGet(metadataKey)
	if !ok {
		return errors.New("file metadata not found @ AppendToFile")
	}
	dataWithSig := &EncryptedMetadataWithSig{}
	json.Unmarshal(dataWithSigBytes, dataWithSig)
	newSignature, _ := userlib.HMACEval(symKey, dataWithSig.EncryptedMetadata)
	isValid := userlib.HMACEqual(dataWithSig.Signature, newSignature)
	if !isValid {
		return errors.New("metadata signature mismatch")
	}

	// Assume DecryptData and EncryptData are implemented correctly elsewhere
	metadataBytes := userlib.SymDec(symKey, dataWithSig.EncryptedMetadata)

	metadata := &FileMetadata{}
	err := json.Unmarshal(metadataBytes, metadata)
	if err != nil {
		return err
	}

	prevTailUUID := metadata.TailUUID

	//get, update, and store the new tail node
	newTailNodeUUID := uuid.New()
	newTailNode := ListNode{Content: content, NextUUID: uuid.Nil, PrevUUID: prevTailUUID}
	newTailNodeBytes, _ := json.Marshal(newTailNode)
	encryptedNewTailNode := userlib.SymEnc(symKey, iv, newTailNodeBytes)
	userlib.DatastoreSet(newTailNodeUUID, encryptedNewTailNode)

	//update previous tail node to point to the new tail if it exists
	if prevTailUUID != uuid.Nil {
		prevTailEncrypted, ok := userlib.DatastoreGet(prevTailUUID)
		if !ok {
			return errors.New("previous tail node not found")
		}

		prevTailNode := &ListNode{}
		prevTailBytes := userlib.SymDec(symKey, prevTailEncrypted)
		json.Unmarshal(prevTailBytes, prevTailNode)
		prevTailNode.NextUUID = newTailNodeUUID //update to point to new tail
		updatedPrevTailBytes, _ := json.Marshal(prevTailNode)
		encryptedUpdatedPrevTail := userlib.SymEnc(symKey, iv, updatedPrevTailBytes)
		userlib.DatastoreSet(prevTailUUID, encryptedUpdatedPrevTail)
	}

	//update metadata to reflect the new tail UUID
	metadata.TailUUID = newTailNodeUUID
	updatedMetadataBytes, _ := json.Marshal(metadata)
	encryptedUpdatedMetadata := userlib.SymEnc(symKey, iv, updatedMetadataBytes)
	signature, _ := userlib.HMACEval(symKey, encryptedUpdatedMetadata)
	newdataWithSig := EncryptedMetadataWithSig{
		EncryptedMetadata: encryptedUpdatedMetadata,
		Signature:         signature,
	}

	newdataWithSigBytes, _ := json.Marshal(newdataWithSig)
	userlib.DatastoreSet(metadataKey, newdataWithSigBytes)

	return nil
}
func (userdata *User) LoadFile(filename string) ([]byte, error) {

	//-----------------VALIDATION-----------
	fileID, inNameSpace := userdata.UserFileSpace[filename]
	if !inNameSpace {
		//if file is NOT in the user's file name space -> NO ACCESS
		// return nil, errors.New(userdata.Username + "has no file named: " + filename + " in its fle name space @LoadFile")
		newData, update := getUserData(*userdata, filename)
		if update != nil {
			return nil, update
		}
		userdata = &newData
		fileID, inNameSpace = newData.UserFileSpace[filename]
		//CHECK AGAIN
		if !inNameSpace {
			return nil, errors.New("Access Denied. No File ID @LoadFile")
		}

	}

	newData, update := getUserData(*userdata, filename)
	if update != nil {
		return nil, update
	}

	userdata = &newData

	metadataKey, hErr := generateMetadataKey(fileID, userdata)
	if hErr != nil {
		return nil, hErr
	}

	//--------------------------------------

	symKey := userdata.SymKey

	// Retrieve the file metadata from the DataStore using the filename

	dataWithSigBytes, ok := userlib.DatastoreGet(metadataKey)
	if !ok {
		return nil, errors.New("file metadata not found @LoadFile")
	}
	dataWithSig := &EncryptedMetadataWithSig{}
	json.Unmarshal(dataWithSigBytes, dataWithSig)

	newSignature, _ := userlib.HMACEval(symKey, dataWithSig.EncryptedMetadata)

	isValid := userlib.HMACEqual(dataWithSig.Signature, newSignature)
	if !isValid {
		return nil, errors.New("metadata signature mismatch")
	}

	//decrypt the metadata to get the head UUID
	metadataBytes := userlib.SymDec(symKey, dataWithSig.EncryptedMetadata)

	metadata := &FileMetadata{}
	err := json.Unmarshal(metadataBytes, metadata)
	if err != nil {
		return nil, err
	}

	//initialize an empty buffer to hold the file content
	var fileContent bytes.Buffer

	//traverse the doubly linked list starting from the head node
	currentNodeUUID := metadata.HeadUUID
	for currentNodeUUID != uuid.Nil {
		//retrieve and decrypt the current node from the DataStore using its UUID
		encryptedNode, ok := userlib.DatastoreGet(currentNodeUUID)
		if !ok {
			return nil, errors.New("failed to retrieve node from DataStore")
		}
		nodeBytes := userlib.SymDec(symKey, encryptedNode)
		if err != nil {
			return nil, err
		}

		node := &ListNode{}
		err = json.Unmarshal(nodeBytes, node)
		if err != nil {
			return nil, err
		}

		//append the content of the current node to the file content buffer
		fileContent.Write(node.Content)

		//move to the next node in the list, if it exists
		if node.NextUUID == uuid.Nil {
			break //this was the last node
		}
		currentNodeUUID = node.NextUUID
	}

	//return the concatenated content of all nodes
	return fileContent.Bytes(), nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {

	if recipientUsername == userdata.Username {
		return uuid.Nil, errors.New("Should not send invitations to itself ")
	}

	fileID, exists := userdata.UserFileSpace[filename]
	if !exists {
		// return uuid.Nil, errors.New(filename + " is NOT in " + userdata.Username + "' FILENAME SPACE @CreateInvitation " + " rec: " + recipientUsername)
		newData, update := getUserData(*userdata, filename)
		if update != nil {
			return uuid.Nil, update
		}
		userdata = &newData
		fileID, exists = newData.UserFileSpace[filename]
		//CHECK AGAIN
		if !exists {
			return uuid.Nil, errors.New("Access Denied. No File ID @CreateInvitation")
		}
	}

	storageKey, _ := uuid.FromBytes(userlib.Hash([]byte("inv" + filename + recipientUsername))[:16])
	//generate metadata key dynamically
	metadataKey, _ := generateMetadataKey(fileID, userdata)
	symKey := userlib.Argon2Key([]byte(userdata.Password), globalSaltTwo, 16)
	iv := userlib.Argon2Key([]byte(userdata.Username+string(userdata.Password)), globalSaltTwo, 16)

	padding, errP := getLocationPadding(userdata, filename, fileID)
	if errP != nil {
		return uuid.Nil, errP
	}

	invitationStruct := &InvitationStruct{
		FileName:    filename,
		FileID:      userdata.UserFileSpace[filename],
		MetaDataKey: metadataKey,
		SymKey:      symKey,
		IV:          iv,
		HMACKey:     globalHmacKey,
		Padding:     padding,
	}

	invitationMarshaled, _ := json.Marshal(invitationStruct)
	publicKey, ok := userlib.KeystoreGet(recipientUsername + "publicKey")
	if !ok {
		return uuid.New(), errors.New("Public Key not found ")
	}

	symPKEKey := userlib.RandomBytes(16)
	ivPKEKey := userlib.RandomBytes(16)
	ciphertext := userlib.SymEnc(symPKEKey, ivPKEKey, invitationMarshaled)
	symKeyEncrypted, err := userlib.PKEEnc(publicKey, symPKEKey)
	signedKey, _ := userlib.DSSign(userdata.UserSignKey, symKeyEncrypted)

	helper := &Helper{
		Ciphertext:      ciphertext,
		SymKeyEncrypted: symKeyEncrypted,
		Signature:       signedKey}
	encryptedStruct, _ := json.Marshal(helper)

	//add invitationPtr nd fileName to the Access Tree
	invStore := storeInvitation(storageKey, filename, recipientUsername, fileID, userdata)
	if invStore != nil {
		return uuid.Nil, invStore
	}

	userlib.DatastoreSet(storageKey, encryptedStruct)

	return storageKey, err
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	//some code to validate that it is coming from the actual user
	encryptedStruct, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("invitation not found")
	}

	helper := &Helper{}
	json.Unmarshal(encryptedStruct, helper)

	verifyKey, ok := userlib.KeystoreGet(senderUsername + "signature")
	if !ok {
		return errors.New("sender not found")
	}
	err := userlib.DSVerify(verifyKey, helper.SymKeyEncrypted, helper.Signature)
	if err != nil {
		return errors.New("failed to verify the sender")
	}

	symPKEKey, _ := userlib.PKEDec(userdata.PKEDecKey, helper.SymKeyEncrypted)
	invitationMarshaled := userlib.SymDec(symPKEKey, helper.Ciphertext)

	invitationStruct := &InvitationStruct{}
	json.Unmarshal(invitationMarshaled, invitationStruct)

	if _, exists := userdata.UserFileSpace[filename]; exists {
		return errors.New("you already have a file with this name")
	}

	userdata.UserFileSpace[filename] = invitationStruct.FileID
	//validate invitation
	findInvInAT, invErr := validateInvitation(invitationPtr, filename, invitationStruct.FileID, senderUsername, *userdata)
	if !findInvInAT {
		return invErr
	}

	newData, update := updateUserData(*userdata, filename, invitationStruct.FileID)
	if update != nil {
		return update
	}
	userdata = &newData
	access := grantAccess(filename, invitationStruct.FileID, invitationStruct.Padding, userdata)
	if access != nil {
		return access
	}

	userlib.DatastoreDelete(invitationPtr)

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {

	//-----------------ERRORS---------------------
	// The given filename does not exist in the caller’s personal file namespace.
	fileID, exists := userdata.UserFileSpace[filename]
	if !exists {
		// return uuid.Nil, errors.New(filename + " is NOT in " + userdata.Username + "' FILENAME SPACE @CreateInvitation " + " rec: " + recipientUsername)
		newData, update := getUserData(*userdata, filename)
		if update != nil {
			return update
		}
		userdata = &newData
		fileID, exists = newData.UserFileSpace[filename]
		//CHECK AGAIN
		if !exists {
			return errors.New("Access Denied. No File ID @CreateInvitation")
		}
	}
	// The given filename is not currently shared with recipientUsername.
	_, errM := generateMetadataKey(fileID, userdata)
	if errM != nil {
		return errM
	}
	// AND
	// Revocation cannot be completed due to malicious action.

	//----######--DELETE THE USER----
	isRevoked := suspendAccess(fileID, recipientUsername, userdata)
	if isRevoked != nil {
		return isRevoked
	}

	fmt.Println("Inv Successfully Revoked")
	return nil

}

// -------------helper functions------------------//

// ---------------Invitation Helper Functions--------------------------------
// Helper function to add an invitation to the invitation map

// Function to validate an invitation
func storeInvitation(invitationPtr uuid.UUID, filename, recipientUsername string, fileID []byte, userdata *User) error {

	fileIDHash := userlib.Hash([]byte(fileID))
	storageKeyForATree, _ := uuid.FromBytes(userlib.Hash([]byte("77" + string(fileIDHash)))[:16])
	accessTreeEnc, errAccess := userlib.DatastoreGet(storageKeyForATree)
	//check if the access file exists
	if !errAccess {
		return errors.New("Access to file denied!! No such access tree exists @storeInvitation")
	}

	// getSignature, noSign := globalAccessTreeSigs[string(fileID)]
	// if !noSign {
	// 	return uuid.Nil, errors.New("No global signature in the map @ ValidateAccess")
	// }
	//check signature
	// verfySign := userlib.DSVerify(globalDSVerifyKey, accessTreeEnc, getSignature)
	// if verfySign != nil {
	// 	return uuid.Nil, errors.New("The Signature is broken @ ValidateAccess")
	// }

	// if the access file exists, check if the user has access to it
	//dec -> unmarshal
	decTree := userlib.SymDec(globalSymAccessKey, accessTreeEnc)
	var unMarshallTree *Tree
	json.Unmarshal(decTree, &unMarshallTree)

	AddInvitationByUsername(unMarshallTree, recipientUsername, userdata.Username, invitationPtr, fileID)

	marshalATree, errMarA := json.Marshal(unMarshallTree)
	if errMarA != nil {
		return errMarA
	}

	// Encrypt the hashed access tree using the owner's symKey and new IV
	newIVforATree := userlib.RandomBytes(16)
	encAccessTree := userlib.SymEnc(globalSymAccessKey, newIVforATree, marshalATree)
	// sign, errS := userlib.DSSign(globalDSSignKey, encAccessTree)
	// if errS != nil {
	// 	return errS
	// }
	// globalAccessTreeSigs[string(fileNameHash)+string(userNameHash)] = sign

	// Store the encrypted access tree to the DataStore
	userlib.DatastoreSet(storageKeyForATree, encAccessTree)
	return nil
}

func validateInvitation(invitationPtr uuid.UUID, filename string, fileID []byte, sender string, userdata User) (bool, error) {
	// Generate storage key for invitations
	fileIDHash := userlib.Hash([]byte(fileID))
	storageKeyForATree, _ := uuid.FromBytes(userlib.Hash([]byte("77" + string(fileIDHash)))[:16])
	accessTreeEnc, errAccess := userlib.DatastoreGet(storageKeyForATree)
	//check if the access file exists
	if !errAccess {
		return false, errors.New("Access to file denied!! No such access tree exists @validateInvitation")
	}

	decTree := userlib.SymDec(globalSymAccessKey, accessTreeEnc)
	var unMarshallTree *Tree
	json.Unmarshal(decTree, &unMarshallTree)

	return InvitationExists(unMarshallTree, sender, userdata.Username, invitationPtr, fileID), nil
}

func suspendAccess(fileID []byte, recipient string, userdata *User) error {
	fileIDHash := userlib.Hash([]byte(fileID))
	storageKeyForATree, _ := uuid.FromBytes(userlib.Hash([]byte("77" + string(fileIDHash)))[:16])
	oldFileLocation, errN := generateMetadataKey(fileID, userdata)
	if errN != nil {
		return errN
	}
	content, errGet := userlib.DatastoreGet(oldFileLocation)
	if !errGet {
		return errors.New("not able to get oldData @ suspendAccess")
	}
	accessTreeEnc, _ := userlib.DatastoreGet(storageKeyForATree)
	decTree := userlib.SymDec(globalSymAccessKey, accessTreeEnc)

	var unMarshallTree *Tree = nil
	json.Unmarshal(decTree, &unMarshallTree)

	DeleteUser(&unMarshallTree, recipient)

	// deleteInvitationByUsername(unMarshallTree, userdata.Username, recipient)
	//fmt.Println("before:")
	// InOrderTraversal(unMarshallTree)
	//update all teh nodes with new padding
	newPadding := userlib.RandomBytes(15)
	updateFileLocation(unMarshallTree, newPadding)

	//delete the invitation from DataStore
	invPtr := getInvitationByUsername(unMarshallTree, recipient, userdata.Username)
	if invPtr == uuid.Nil {
		deleteInvitationByUsername(unMarshallTree, userdata.Username, recipient)
	}
	userlib.DatastoreDelete(invPtr)

	//fmt.Println("after:")
	//fmt.Println("padding updated")
	// InOrderTraversal(unMarshallTree)
	// Convert the tree to binary
	marshalATree, _ := json.Marshal(&unMarshallTree)
	//encrypt
	newIV := userlib.RandomBytes(16)
	encAccessTree := userlib.SymEnc(globalSymAccessKey, newIV, marshalATree)
	// sign, errS := userlib.DSSign(globalDSSignKey, encAccessTree)
	// if errS != nil {
	// 	return errS
	// }
	// globalAccessTreeSigs[string(fileNameHash)+string(userNameHash)] = sign

	// Store the encrypted access tree in the DataStore
	fmt.Println(string(fileID) + "stored to new location")
	newFileLocation, errN := uuid.FromBytes(userlib.Hash([]byte(string(fileID) + string(newPadding)))[:16])
	if errN != nil {
		return errN
	}
	//store the file content to a new location
	userlib.DatastoreSet(newFileLocation, content)
	//store the updated access tree
	userlib.DatastoreSet(storageKeyForATree, encAccessTree)
	//delete the old location with file content
	userlib.DatastoreDelete(oldFileLocation)

	accessTreeEnc, err := userlib.DatastoreGet(oldFileLocation)
	if !err {
		fmt.Println("Old storage deleted")
	}

	return nil
}

func generateMetadataKey(fileID []byte, userdata *User) (uuid.UUID, error) {

	// userNameHash := userlib.Hash([]byte(userdata.Username))
	fileIDHash := userlib.Hash([]byte(fileID))
	storageKeyForATree, _ := uuid.FromBytes(userlib.Hash([]byte("77" + string(fileIDHash)))[:16])
	accessTreeEnc, errAccess := userlib.DatastoreGet(storageKeyForATree)

	fileLocation, err := uuid.FromBytes(userlib.Hash([]byte("00")))
	//check if the access file exists
	if !errAccess {
		return uuid.Nil, errors.New("Access to file denied!! No such access tree exists @generateMetadataKey")
	}

	// getSignature, noSign := globalAccessTreeSigs[string(fileID)]
	// if !noSign {
	// 	return uuid.Nil, errors.New("No global signature in the map @ ValidateAccess")
	// }
	//check signature
	// verfySign := userlib.DSVerify(globalDSVerifyKey, accessTreeEnc, getSignature)
	// if verfySign != nil {
	// 	return uuid.Nil, errors.New("The Signature is broken @ ValidateAccess")
	// }

	// if the access file exists, check if the user has access to it
	//dec -> unmarshal
	decTree := userlib.SymDec(globalSymAccessKey, accessTreeEnc)
	var unMarshallTree *Tree
	json.Unmarshal(decTree, &unMarshallTree)
	//fmt.Println(" generating metadata key: " + userdata.Username)
	// InOrderTraversal(unMarshallTree)

	getFileLocation := SearchByUsername(unMarshallTree, userdata.Username)
	if getFileLocation == nil {
		return uuid.Nil, errors.New(string(userdata.Username) + " has no access to " + string(fileID) + "@generateMetadataKey")
	}
	fmt.Println("user successfully validated")
	fileLocation, err = uuid.FromBytes(userlib.Hash([]byte(string(getFileLocation.FileID) + string(getFileLocation.Padding)))[:16])

	return fileLocation, err
}

// TREE IMPLEMENTATION --------------

type Tree struct {
	Data  DataAccess
	Left  *Tree
	Right *Tree
}

func NewNode(data DataAccess) *Tree {
	return &Tree{Data: data, Left: nil, Right: nil}
}

// Function to insert a new node into the tree
func Insert(root *Tree, data DataAccess) *Tree {
	if root == nil {
		return NewNode(data)
	}

	// Perform insertion based on the name
	if data.FileName < root.Data.FileName {
		root.Left = Insert(root.Left, data)
	} else {
		root.Right = Insert(root.Right, data)
	}

	return root
}

func InOrderTraversal(root *Tree) {
	if root != nil {
		InOrderTraversal(root.Left)
		//fmt.Printf("File Padding`: %s\n", string(root.Data.Padding))
		InOrderTraversal(root.Right)
	}
}

// Function to search for a specific username in the tree
// Helper function to search for a specific username in the tree
func SearchByUsername(root *Tree, username string) *DataAccess {
	if root == nil {
		return nil
	}

	// If the current node's username matches the target username, return its data
	if root.Data.UserName == username {
		return &root.Data
	}

	// Recursively search in the left subtree
	leftResult := SearchByUsername(root.Left, username)
	if leftResult != nil {
		return leftResult
	}

	// Recursively search in the right subtree
	rightResult := SearchByUsername(root.Right, username)
	if rightResult != nil {
		return rightResult
	}

	// If username is not found in this subtree, return nil
	return nil
}

func DeleteUser(root **Tree, username string) *Tree {
	if *root == nil {
		return nil
	}

	if (*root).Data.UserName == username {
		// Delete the node and its subtree
		*root = nil
		return nil
	}

	(*root).Left = DeleteUser(&(*root).Left, username)
	(*root).Right = DeleteUser(&(*root).Right, username)

	// If the current node was not deleted, return it
	return *root
}

func InvitationExists(root *Tree, sender, rec string, invPtr uuid.UUID, fileID []byte) bool {
	if root == nil {
		return false
	}

	if root.Data.UserName == sender {
		// Check if Invitations map exists and contains the key-value pair
		if root.Data.Invitations != nil {
			if val, ok := root.Data.Invitations[rec]; ok && val == invPtr {
				return true
			}
		}
	}

	if InvitationExists(root.Left, sender, rec, invPtr, fileID) {
		return true
	}

	// Recursively search in the right subtree
	if InvitationExists(root.Right, sender, rec, invPtr, fileID) {
		return true
	}

	return false
}

// Helper function to get the file ID from the root node of the tree
func getPadding(root *Tree) []byte {
	if root != nil {
		return root.Data.Padding
	}
	return nil
}

func getLocationPadding(userdata *User, filename string, fileID []byte) ([]byte, error) {

	fileIDHash := userlib.Hash([]byte(fileID))
	storageKeyForATree, err := uuid.FromBytes(userlib.Hash([]byte("77" + string(fileIDHash)))[:16])

	if err != nil {
		return []byte("0"), err
	}

	accessTreeEnc, errAccess := userlib.DatastoreGet(storageKeyForATree)
	//check if the access file exists
	if !errAccess {
		return []byte("0"), errors.New("Access to file denied!! No such access tree exists @  getLocationPadding")
	}

	decTree := userlib.SymDec(globalSymAccessKey, accessTreeEnc)
	var unMarshallTree *Tree = nil
	json.Unmarshal(decTree, &unMarshallTree)

	padding := getPadding(unMarshallTree)
	if padding == nil {
		return nil, errors.New("Could not retrieve the padding")
	}
	//fmt.Println("Padding: " + string(padding))

	return padding, nil

}

func updateFileLocation(root *Tree, newPadding []byte) {
	if root == nil {
		return
	}

	// Update the padding of the current node
	root.Data.Padding = newPadding

	// Recursively update padding in left subtree
	updateFileLocation(root.Left, newPadding)

	// Recursively update padding in right subtree
	updateFileLocation(root.Right, newPadding)
}

// Helper function to search for a specific username in the tree and add an invitation
func AddInvitationByUsername(root *Tree, rec, sender string, invPtr uuid.UUID, fileID []byte) *Tree {
	if root == nil {
		return nil
	}

	// If the current node's username matches the target username
	if root.Data.UserName == sender {
		// If Invitations map is nil, create a new map
		if root.Data.Invitations == nil {
			root.Data.Invitations = make(map[string]uuid.UUID)
		}
		// Add the invitation to the map
		root.Data.Invitations[rec] = invPtr
	}

	// Recursively search in the left subtree
	root.Left = AddInvitationByUsername(root.Left, rec, sender, invPtr, fileID)

	// Recursively search in the right subtree
	root.Right = AddInvitationByUsername(root.Right, rec, sender, invPtr, fileID)

	return root
}

func getInvitationByUsername(root *Tree, rec, sender string) uuid.UUID {
	if root == nil {
		return uuid.Nil
	}

	// If the current node's username matches the target username
	if root.Data.UserName == sender && root.Data.Invitations != nil {
		// Check if the recipient is in the invitations map
		if invitation, ok := root.Data.Invitations[rec]; ok {
			return invitation // Return the invitation if found
		}
	}

	// Recursively search in the left subtree
	invitation := getInvitationByUsername(root.Left, rec, sender)
	if invitation != uuid.Nil {
		return invitation // Return if found in the left subtree
	}

	// Recursively search in the right subtree
	return getInvitationByUsername(root.Right, rec, sender) // Return if found in the right subtree
}

// Helper function to search for a specific username in the tree and delete an invitation
func deleteInvitationByUsername(root *Tree, username string, recipient string) *Tree {
	if root == nil {
		return nil
	}

	// If the current node's username matches the target username
	if root.Data.UserName == username {
		// If Invitations map exists and contains the key, delete it
		if root.Data.Invitations != nil {
			delete(root.Data.Invitations, recipient)
		}
	}

	// Recursively search in the left subtree
	root.Left = deleteInvitationByUsername(root.Left, username, recipient)

	// Recursively search in the right subtree
	root.Right = deleteInvitationByUsername(root.Right, username, recipient)

	return root
}

//------------------END TREE IMPLEMENTATION ------------------------------//
//------------------------------------------------------------------------//

// ------------Access Helper Functions--------------------------------
// Helper function to create an access tree
func CreateAccessTree(userdata *User, filename string, fileID []byte, padding []byte) error {
	// Calculate hashes for filename and username
	// fileNameHash := userlib.Hash([]byte(filename))
	// userNameHash := userlib.Hash([]byte(userdata.Username))
	newInvMap := make(map[string]uuid.UUID)
	// Create a new access tree node
	var newTree *Tree

	newAccessTree := DataAccess{
		FileID:      fileID,
		FileName:    filename,
		UserName:    userdata.Username,
		Invitations: newInvMap,
		Padding:     padding,
	}

	newTree = Insert(newTree, newAccessTree)
	fmt.Printf("new tree has been created for" + userdata.Username)

	// InOrderTraversal(newTree)

	fileIDHash := userlib.Hash([]byte(fileID))
	// Generate storage key for the access tree
	storageKeyForATree, err := uuid.FromBytes(userlib.Hash([]byte("77" + string(fileIDHash)))[:16])
	if err != nil {
		return err
	}

	// Convert the tree to binary
	marshalATree, errMarA := json.Marshal(newTree)
	if errMarA != nil {
		return errMarA
	}

	// Encrypt the hashed access tree using the owner's symKey and new IV
	newIVforATree := userlib.RandomBytes(16)
	encAccessTree := userlib.SymEnc(globalSymAccessKey, newIVforATree, marshalATree)
	// sign, errS := userlib.DSSign(globalDSSignKey, encAccessTree)
	// if errS != nil {
	// 	return errS
	// }
	// globalAccessTreeSigs[string(fileNameHash)+string(userNameHash)] = sign

	// Store the encrypted access tree to the DataStore
	userlib.DatastoreSet(storageKeyForATree, encAccessTree)

	return nil
}

func grantAccess(filename string, fileID []byte, padding []byte, userdata *User) error {

	fileIDHash := userlib.Hash([]byte(fileID))
	storageKeyForATree, err := uuid.FromBytes(userlib.Hash([]byte("77" + string(fileIDHash)))[:16])
	if err != nil {
		return err
	}
	accessTreeEnc, errAccess := userlib.DatastoreGet(storageKeyForATree)

	//check if the access file exists
	if !errAccess {
		return errors.New("Access to file denied!! No such access tree exists @grantAccess")
	}

	decTree := userlib.SymDec(globalSymAccessKey, accessTreeEnc)
	var unMarshallTree *Tree = nil
	json.Unmarshal(decTree, &unMarshallTree)

	newInvMap := make(map[string]uuid.UUID)
	newAccessTree := DataAccess{
		FileID:      fileID,
		FileName:    filename,
		UserName:    userdata.Username,
		Invitations: newInvMap,
		Padding:     padding,
	}

	unMarshallTree = Insert(unMarshallTree, newAccessTree)
	// Convert the tree to binary
	marshalATree, _ := json.Marshal(unMarshallTree)
	//encrypt
	newIV := userlib.RandomBytes(16)
	encAccessTree := userlib.SymEnc(globalSymAccessKey, newIV, marshalATree)

	// Store the encrypted access tree in the DataStore
	userlib.DatastoreSet(storageKeyForATree, encAccessTree)

	return nil
}

//----------------------------------------------------------------------------

func RandomBytes(length int) []byte {

	// Create a byte slice of the specified length
	randomBytes := userlib.RandomBytes(length)

	// Convert the byte slice to a string and return it
	return randomBytes
}

// use tree to revoke and manage access
