#include "ACMatch.hh"
#include "PCREMatch.hh"

int main() {
  Packet pac;
  (new ACMatch)->process(10087, &pac);
  (new PCREMatch)->process(10087, &pac);
}