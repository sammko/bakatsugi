#ifndef BAKATSUGI_H
#define BAKATSUGI_H
#define BAKATSUGI(__X) const char __bakatsugi_patches[] __attribute__((section("bakatsugi"))) = __X;
#define PATCH_OWN(orig, replace) "O" #orig "." #replace "\n"
#define PATCH_LIB(orig, replace) "L" #orig "." #replace "\n"
#endif
