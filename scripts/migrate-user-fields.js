/**
 * This script migrates user data from firstName to userName
 * Run this on your MongoDB database to update existing records
 */

// Fix: Remove "MONGODB_URI=" from the connection string
const MONGODB_URI =
    process.env.MONGODB_URI ||
    "mongodb+srv://finders:findersdb@nestdb.ukftfc6.mongodb.net/findmydeviceng?retryWrites=true&w=majority"

// Fix: Use require instead of import for CommonJS compatibility
const { MongoClient } = require("mongodb")

async function migrateUserFields() {
    console.log("Starting migration from firstName to userName...")

    const client = new MongoClient(MONGODB_URI)

    try {
        await client.connect()
        console.log("Connected to MongoDB")

        const db = client.db()
        const usersCollection = db.collection("users")

        // Find all users with firstName but no userName
        const users = await usersCollection
            .find({
                firstName: { $exists: true },
                userName: { $exists: false },
            })
            .toArray()

        console.log(`Found ${users.length} users to migrate`)

        if (users.length === 0) {
            console.log("No users need migration. Exiting.")
            return
        }

        // Update each user
        let successCount = 0
        let errorCount = 0

        for (const user of users) {
            try {
                const result = await usersCollection.updateOne(
                    { _id: user._id },
                    {
                        $set: { userName: user.firstName },
                        $unset: { firstName: "" },
                    },
                )

                if (result.modifiedCount > 0) {
                    successCount++
                    console.log(`Migrated user: ${user._id} - ${user.email} (${user.firstName} -> userName)`)
                }
            } catch (err) {
                errorCount++
                console.error(`Error migrating user ${user._id}:`, err)
            }
        }

        console.log("\nMigration complete:")
        console.log(`- Total users processed: ${users.length}`)
        console.log(`- Successfully migrated: ${successCount}`)
        console.log(`- Errors: ${errorCount}`)
    } catch (err) {
        console.error("Migration failed:", err)
    } finally {
        await client.close()
        console.log("Disconnected from MongoDB")
    }
}

// Run the migration
migrateUserFields().catch(console.error)
