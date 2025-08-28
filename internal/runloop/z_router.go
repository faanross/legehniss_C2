package runloop

import "fmt"

// zValueDispatcher performs actions based on the Z-value received
func zValueDispatcher(z uint8) {
	switch z {
	case 0:
		zValue0Called()
	case 1:

		zValue1Called()
	case 2:
		zValue2Called()
	case 3:
		zValue3Called()
	case 4:
		zValue4Called()
	case 5:
		zValue5Called()
	case 6:
		zValue6Called()
	case 7:
		zValue7Called()
	default:
		fmt.Println("An invalid Z-value was received")
	}
}

func zValue0Called() {
	fmt.Println("The Z-value of 0 was received")
}

func zValue1Called() {
	fmt.Println("The Z-value of 1 was received")
}

func zValue2Called() {
	fmt.Println("The Z-value of 2 was received")
}

func zValue3Called() {
	fmt.Println("The Z-value of 3 was received")
}

func zValue4Called() {
	fmt.Println("The Z-value of 4 was received")
}

func zValue5Called() {
	fmt.Println("The Z-value of 5 was received")
}

func zValue6Called() {
	fmt.Println("The Z-value of 6 was received")
}

func zValue7Called() {
	fmt.Println("The Z-value of 7 was received")
}
