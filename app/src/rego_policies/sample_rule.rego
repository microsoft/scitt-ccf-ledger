package sample

import future.keywords.if
import future.keywords.in

default allowed := false

# Allow if SCITT version exists in the input
allowed if {
    not empty(input.scitt)
    contains(input.scitt, "test")
}
