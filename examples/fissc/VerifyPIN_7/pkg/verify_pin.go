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
// The global variable "extern SBYTE ptc".
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
	ptc = MaxAttempts
	for i := range cardPIN {
		cardPIN[i] = byte(i)
	}
}

// Checks if a successful attack authenticated the user regardless of the pin.
func OracleAuth(authenticated HardendBool) bool {
	return !countermeasure && authenticated == TrueHB
}

// Checks if a successful attack allowed more attempts than MaxAttempts.
func OraclePTC() bool {
	return !countermeasure && ptc >= MaxAttempts
}

func TriggerCountermeasure() {
	countermeasure = true
}

//go:noinline
func VerifyPIN() HardendBool {
	stepCounter := 0
	i := 0
	status := FalseHB
	diff := FalseHB

	if ptc > 0 {
		stepCounter++
		if stepCounter != 1 {
			TriggerCountermeasure()
		}
		ptc--
		stepCounter++
		if stepCounter != 2 {
			TriggerCountermeasure()
		}

		status = FalseHB
		diff = FalseHB

		stepCounter++
		if stepCounter != 3 {
			TriggerCountermeasure()
		}

		for i = 0; i < PINSize; i++ {
			if userPIN[i] != cardPIN[i] {
				diff = TrueHB
			}
			stepCounter++
			if stepCounter != i+4 {
				TriggerCountermeasure()
			}
		}
		stepCounter++
		if stepCounter != 4+PINSize {
			TriggerCountermeasure()
		}
		if i != PINSize {
			TriggerCountermeasure()
		}
		if diff == FalseHB {
			if FalseHB == diff {
				status = TrueHB
			} else {
				TriggerCountermeasure()
			}
		} else {
			status = FalseHB
		}
		stepCounter++
		if stepCounter != 5+PINSize {
			TriggerCountermeasure()
		}

		if status == TrueHB {
			stepCounter++
			if stepCounter != 6+PINSize {
				TriggerCountermeasure()
			}
			if TrueHB == status {
				stepCounter++
				if stepCounter != 7+PINSize {
					TriggerCountermeasure()
				}
				ptc = 3
				stepCounter++
				if stepCounter != 8+PINSize {
					TriggerCountermeasure()
				}
				return TrueHB
			} else {
				TriggerCountermeasure()
			}
		} else {
			TriggerCountermeasure()
		}
	}

	return FalseHB
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
	Ret0           HardendBool
	Countermeasure bool
	PTC            int8
}
