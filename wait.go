package main

import (
	"fmt"
	"io"
	"math/big"
	"os"
	"os/signal"
	"time"
)

type Wait struct {
	Seconds int
	Out     io.Writer
}

func (w Wait) Start() {
	duration := time.Duration(w.Seconds) * time.Second
	startTime := time.Now()
	endTime := startTime.Add(duration)

	w.write(endTime)

	i := int64(1)
	ticker := time.NewTicker(1 * time.Second)

	ctrlc := make(chan os.Signal, 1)
	signal.Notify(ctrlc, os.Interrupt)

	for {
		select {
		case <-ticker.C:
			i++
			w.write(endTime)
			if i > int64(duration/time.Second) {
				fmt.Fprintf(w.Out, "\nTime's up...\n")
				ticker.Stop()
				return
			}
		case <-ctrlc:
			fmt.Fprintf(w.Out, "\nCTRL-C catched, stopped...\n")
			ticker.Stop()
			return
		}
	}
}

func (w Wait) write(t time.Time) {
	h := big.NewInt(int64(time.Until(t).Hours()))
	m := big.NewInt(int64(time.Until(t).Minutes()))
	s := big.NewInt(int64(time.Until(t).Seconds()))
	s = s.Mod(s, big.NewInt(60))
	m = m.Mod(m, big.NewInt(60))
	fmt.Fprintf(w.Out, "\r%02d:%02d:%02d", h, m, s)
}
