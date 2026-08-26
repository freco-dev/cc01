package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	cc01v1 "github.com/freco-dev/cc01/proto/gen/cc01/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// upTimeout — ko'tarilish CP bilan gaplashadi, TUN yaratadi va
// marshrut qo'yadi. Demon tomonida ham chegara bor; bu yerdagisi
// undan uzunroq, aks holda CLI demon hali ishlab turganda taslim
// bo'lardi va foydalanuvchi natijani ko'rmay qolardi.
const upTimeout = 45 * time.Second

func runUp(args []string) error {
	set := flag.NewFlagSet("up", flag.ContinueOnError)
	socket := socketFlag(set)
	if err := set.Parse(args); err != nil {
		return err
	}

	client, closeConn, err := connect(*socket)
	if err != nil {
		return err
	}
	defer closeConn()

	ctx, cancel := context.WithTimeout(context.Background(), upTimeout)
	defer cancel()

	response, err := client.Up(ctx, &cc01v1.UpRequest{})
	if err != nil {
		if status.Code(err) == codes.AlreadyExists {
			// Bu holat foydalanuvchi uchun xato emas: mesh
			// allaqachon ishlayapti. Lekin buyruq hech narsa
			// qilmaganini aytish kerak.
			fmt.Println("mesh allaqachon ko'tarilgan")
			return nil
		}
		return err
	}

	return printStatus(response.GetStatus(), false)
}

func runDown(args []string) error {
	set := flag.NewFlagSet("down", flag.ContinueOnError)
	socket := socketFlag(set)
	if err := set.Parse(args); err != nil {
		return err
	}

	client, closeConn, err := connect(*socket)
	if err != nil {
		return err
	}
	defer closeConn()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	response, err := client.Down(ctx, &cc01v1.DownRequest{})
	if err != nil {
		return err
	}

	if response.GetAlreadyDown() {
		fmt.Println("mesh allaqachon tushirilgan")
		return nil
	}

	fmt.Println("mesh tushirildi")
	return nil
}
