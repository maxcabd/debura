// Minimal ground-truth fixture for M7 (Type Recovery): single inheritance,
// a virtual method (giving both classes a vtable and RTTI), a non-virtual
// method, and one field per class. Entity's `health` is inherited by
// Player at the same offset; Player adds `ammo` of its own.
//
// Ground truth for evaluating recovered facts against (PROJECT.md S32-33):
//   Player : public Entity
//   Entity::health  (float,  offset 0x8 -- 0x0 is the vtable pointer)
//   Player::ammo    (int,    offset 0xc)
//
// Build (MinGW-w64 g++, Itanium ABI -- MSVC's RTTI/vtable layout differs
// and isn't what ExtractFacts.py parses):
//   g++ -O0 -o entity_player.exe entity_player.cpp

#include <cstdio>

class Entity {
public:
    Entity(float health) : health(health) {}
    virtual ~Entity() {}
    virtual void describe() {
        printf("Entity with %f health\n", health);
    }

protected:
    float health;
};

class Player : public Entity {
public:
    Player(float health, int ammo) : Entity(health), ammo(ammo) {}
    ~Player() override {}
    void describe() override {
        printf("Player with %f health and %d ammo\n", health, ammo);
    }
    void takeDamage(float amount) {
        health -= amount;
    }

private:
    int ammo;
};

int main() {
    Player p(100.0f, 30);
    p.takeDamage(25.0f);
    p.describe();
    return 0;
}
