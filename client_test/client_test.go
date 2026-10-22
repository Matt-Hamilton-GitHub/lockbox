package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
var defaultPassword = string(userlib.RandomBytes(15))

const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"
const FBIAgentSecurityCode = "1234"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var doris *client.User
	var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var bobPhone *client.User
	var charlesLaptop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	dorisFile := "dorisFile.txt"
	eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			//our testing code

			userlib.DebugMsg("Checking that Bob can load the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())
			userlib.DebugMsg("Checking that Charles can load the file.")
			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Bob can't accept invitation again")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

		})

		Specify("Test case we have created", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			//our testing code

			userlib.DebugMsg("Checking that Bob can load the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Bob can't accept invitation again")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

		})

		Specify("Test I: Access Check! ", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, Doris, and Eve")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			bobsSecret := "Bob's darkest secret"
			userlib.DebugMsg("Bob storing file %s with content: %s ", bobFile, bobsSecret)
			err = bob.StoreFile(bobFile, []byte(bobsSecret))
			Expect(err).To(BeNil())

			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			aliceContent := "I am a hacker"
			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, aliceContent)
			err = alice.StoreFile(aliceFile, []byte(aliceContent))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing to Bob's private file %s that she has NO acces to:", bobFile)
			err = alice.StoreFile(bobFile, []byte("I know your secret"))
			Expect(err).To(BeNil())
			mData := "I know your secret"
			Expect(mData).ToNot(Equal([]byte(bobFile)))

			userlib.DebugMsg("Doris storing file %s with content: %s", dorisFile)
			err = doris.StoreFile(dorisFile, []byte(FBIAgentSecurityCode))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice tries to load Doris' file  %s. Without having access to it", dorisFile)
			data, err := alice.LoadFile(dorisFile)
			Expect(err).ToNot(BeNil())
			Expect(data).ToNot(Equal([]byte(dorisFile)))

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("AliceLaptop tries to append Doris' file  %s.", dorisFile)
			err = aliceLaptop.AppendToFile(dorisFile, []byte("$$$$$$"))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Eve tries to load Doris' file  %s.", dorisFile)
			data, err = eve.LoadFile(dorisFile)
			Expect(err).ToNot(BeNil())
			Expect(data).ToNot(Equal([]byte(FBIAgentSecurityCode)))

			addSecurity := "567"
			userlib.DebugMsg("Doris appending to file %s, content: %s", dorisFile, addSecurity)
			err = doris.AppendToFile(dorisFile, []byte(addSecurity))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Doris can load the file and see changes in it.")
			data, err = doris.LoadFile(dorisFile)
			Expect(err).To(BeNil())
			Expect(data).ToNot(Equal([]byte(FBIAgentSecurityCode)))

			userlib.DebugMsg("Doris creating invite for Charles (User That does not exist yet) for file %s, and Charlie accepting invite under name %s.", dorisFile, charlesFile)
			inviteC, err := doris.CreateInvitation(dorisFile, "charles")
			Expect(err).ToNot(BeNil())

			err = charles.AcceptInvitation("charles", inviteC, charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Doris revokies Eve's access from %s. Eve had never had access to it", FBIAgentSecurityCode)
			err = doris.RevokeAccess(FBIAgentSecurityCode, "eve")
			Expect(err).ToNot(BeNil())

		})

		Specify("Test II: Invitation Check! ", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Eve")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			aliceSecret := "I am a witch"
			userlib.DebugMsg("Alice storing file %s with content: %s ", aliceFile, aliceSecret)
			err = alice.StoreFile(aliceFile, []byte(aliceSecret))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s,", aliceFile)
			inviteB, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Eve for file %s,", aliceFile)
			inviteE, err := alice.CreateInvitation(aliceFile, "eve")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepts the invite for file %s,", bobFile)
			err = bob.AcceptInvitation("alice", inviteB, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revokes the invitation for Eve before she accepts the invite for file %s,", aliceFile)
			err = alice.RevokeAccess(aliceFile, "eve")
			Expect(err).To(BeNil())

			userlib.DebugMsg("But now Eve want to accept the invite for file %s,", aliceFile)
			err = eve.AcceptInvitation("alice", inviteE, aliceFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file that she has no access to %s,", eveFile)
			inviteB2, err := alice.CreateInvitation(eveFile, "bob")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob tries to accept the invite for file %s,", eveFile)
			err = bob.AcceptInvitation("alice", inviteB2, eveFile)
			Expect(err).ToNot(BeNil())

			eveCont := "I love cats"
			eveFile2 := "eveSecret.txt"
			userlib.DebugMsg("Eve storing file %s with content: %s ", eveFile, eveCont)
			err = eve.StoreFile(eveFile, []byte(eveCont))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Eve storing file %s with content: %s ", eveFile2, eveCont)
			err = eve.StoreFile(eveFile2, []byte(eveCont))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Eve creating invite for Alice for file %s,", eveFile)
			inviteA, err := eve.CreateInvitation(eveFile, "alice")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice accepts the invite for file %s,", eveFile)
			err = alice.AcceptInvitation("eve", inviteA, eveFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice accepts the invite for file %s,", eveFile)
			err = alice.AcceptInvitation("eve", inviteA, eveFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice tries to access the other files of eve file %s, with no access to it", eveFile2)
			err = alice.AcceptInvitation("eve", inviteA, eveFile2)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Bob tries to revoke Alice access to  %s,", eveFile)
			err = bob.RevokeAccess(eveFile, "alice")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Eve revokes Alice access to  %s,", eveFile)
			err = eve.RevokeAccess(eveFile, "alice")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s ", eveFile, aliceSecret)
			err = alice.StoreFile(eveFile, []byte(aliceSecret))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice appends file %s with content: %s ", eveFile, aliceSecret)
			err = alice.AppendToFile(eveFile, []byte(aliceSecret))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice loads file %s with content: ", eveFile)
			data, err := alice.LoadFile(eveFile)
			Expect(err).ToNot(BeNil())
			Expect(data).ToNot(Equal(eveFile))

			userlib.DebugMsg("Getting second instance of Bob - bobPhone")
			bobPhone, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Charles - charlesLaptop")
			charlesLaptop, err = client.GetUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles storing file %s with content: %s ", charlesFile, eveCont)
			err = charles.StoreFile(charlesFile, []byte(eveCont))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Charles storing file %s with content: %s ", charlesFile, eveCont)
			err = charlesLaptop.StoreFile(charlesFile, []byte(eveCont))
			Expect(err).To(BeNil())

			userlib.DebugMsg("C creating invite for CLaptop for file %s,", charlesFile)
			inviteCh, err := charlesLaptop.CreateInvitation(charlesFile, "charles")
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("CH accepts the invite for file %s,", charlesFile)
			err = charles.AcceptInvitation("charles", inviteCh, charlesFile)
			Expect(err).ToNot(BeNil())

			newCont := "secret"
			userlib.DebugMsg("CHLaptop appends file %s with content: %s ", charlesFile, newCont)
			err = charlesLaptop.AppendToFile(charlesFile, []byte(newCont))
			Expect(err).To(BeNil())

			userlib.DebugMsg("C creating invite for BOB for file %s,", charlesFile)
			inviteB3, err := charlesLaptop.CreateInvitation(charlesFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("CH accepts the invite for file %s,", charlesFile)
			err = bobPhone.AcceptInvitation("charles", inviteB3, charlesFile)
			Expect(err).To(BeNil())

			bobCont := "love spaghetti"
			userlib.DebugMsg("bobPhone appends file %s with content: %s ", charlesFile, bobCont)
			err = bobPhone.AppendToFile(charlesFile, []byte(bobCont))
			Expect(err).To(BeNil())

			userlib.DebugMsg("charlesLaptop loads file %s with content: ", charlesFile)
			data2, err := charlesLaptop.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data2).To(Equal([]byte("I love catssecretlove spaghetti")))

			userlib.DebugMsg("charlesLaptop revokes bobPhone access to  %s,", charlesFile)
			err = charlesLaptop.RevokeAccess(charlesFile, "bob")
			Expect(err).To(BeNil())

			bobCont = "i lied about spaghetti"
			userlib.DebugMsg("bob appends file %s with content: %s ", charlesFile, bobCont)
			err = bob.AppendToFile(charlesFile, []byte(bobCont))
			Expect(err).ToNot(BeNil())

			bobCont = "i lied about laying about spaghetti"
			userlib.DebugMsg("bobPhone appends file %s with content: %s ", charlesFile, bobCont)
			err = bobPhone.AppendToFile(charlesFile, []byte(bobCont))
			Expect(err).ToNot(BeNil())
		})

	})
})
