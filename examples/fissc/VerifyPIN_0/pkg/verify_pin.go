package pkg

// The required pin size from the user and the length of the pin used by the card.
//
// The #define directive "PIN_SIZE" which is "4".
const PINSize = 4

// The allowed number of attempts before user is locked-out.
const MaxAttempts = 3

// The pin try counter (or ptc). This variable describes
// how many times one can attempt the verificaiton of a pin.
// It is reset to MaxAttempts when a correct pin has been entered.
//
// The global variable "extern SBYTE g_ptc".
var ptc int8 = MaxAttempts

// The card pin the user must match inorder to be authenticated.
//
// The global variable "extern UBYTE g_cardPin[PIN_SIZE]".
var cardPIN [PINSize]byte

// The user entered pin.
//
// The global variable "extern UBYTE g_userPin[PIN_SIZE]".
var userPIN [PINSize]byte

// A flip used to describe if a countermeasure was activated.
// If true then a countermeasure was activated. Otherwise, not.
//
// The global variable "extern UBYTE g_countermeasure".
var countermeasure bool

func init() {
	Init()
}

func Init() {
	ptc = MaxAttempts
	for i := range cardPIN {
		cardPIN[i] = byte(i)
	}
}

// Checks if a successful attack authenticated the user regardless of the pin.
func OracleAuth(authenticated bool) bool {
	return !countermeasure && authenticated
}

// Checks if a successful attack allowed more attempts than MaxAttempts.
func OraclePTC() bool {
	return !countermeasure && ptc >= MaxAttempts
}

func TriggerCountermeasure() {
	countermeasure = true
}

//go:noinline
func PINCompare(a1 [PINSize]byte, a2 [PINSize]byte, size int) bool {
	for i := 0; i < size; i++ {
		if a1[i] != a2[i] {
			return false
		}
	}
	return true
}

//go:noinline
func VerifyPIN() bool {
	if ptc > 0 {
		if PINCompare(userPIN, cardPIN, PINSize) {
			ptc = MaxAttempts
			return true
		} else {
			ptc--
			return false
		}
	}

	return false
}

type VerifyPINInput struct {
	UserPIN [PINSize]byte
}

func (input VerifyPINInput) Call() VerifyPINOutput {
	userPIN = input.UserPIN
	ret0 := VerifyPIN()
	return VerifyPINOutput{
		Ret0:           ret0,
		Countermeasure: countermeasure,
		PTC:            ptc,
	}
}

type VerifyPINOutput struct {
	Ret0           bool
	Countermeasure bool
	PTC            int8
}
